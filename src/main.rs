// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
use aws_lambda_events::event::cloudwatch_events::CloudWatchEvent;
use aws_sdk_elasticloadbalancingv2::types::TargetHealthStateEnum as TargetHealth;
use envconfig::Envconfig;
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use mysql::prelude::*;
use mysql::*;
use serde::Deserialize;
use tracing::info;

#[derive(Envconfig)]
pub struct Config {
    #[envconfig(from = "TARGET_GROUP_ARN")]
    pub target_group_arn: String,
    #[envconfig(from = "SECRET_ID")]
    pub secret_id: String,
    #[envconfig(from = "QUERY_TIMEOUT")]
    pub query_timeout: u32,
    #[envconfig(from = "LOG_LEVEL")]
    pub log_level: tracing::Level,
}

#[derive(Deserialize)]
struct DbCredentials {
    user: String,
    password: String,
    host: String,
    port: u16,
}

#[derive(Debug, PartialEq, Eq)]
struct Process {
    id: u32,
    user: String,
    host: Option<String>,
    db: Option<String>,
    command: String,
    time: u32,
    state: String,
    info: Option<String>,
}

struct Instance {
    id: String,
    ip: String,
}

impl From<aws_sdk_ec2::types::Instance> for Instance {
    fn from(i: aws_sdk_ec2::types::Instance) -> Self {
        Self {
            id: i.instance_id.unwrap(),
            ip: i.private_ip_address.unwrap().parse().unwrap(),
        }
    }
}

async fn get_unhealthy_instances_from_target_group(
    client: &aws_sdk_elasticloadbalancingv2::Client,
    target_group_arn: &str,
) -> Result<Vec<String>, Error> {
    let resp = client
        .describe_target_health()
        .target_group_arn(target_group_arn)
        .send()
        .await?;

    let unhealthy_targets = resp
        .target_health_descriptions
        .unwrap()
        .into_iter()
        .filter(|targets| {
            matches!(
                targets.target_health.clone().unwrap().state.unwrap(),
                TargetHealth::Unhealthy
            )
        })
        .map(|targets| targets.target.unwrap().id.unwrap())
        .collect();

    Ok(unhealthy_targets)
}

async fn get_instances_from_instance_ids(
    client: &aws_sdk_ec2::Client,
    instance_ids: Vec<String>,
) -> Result<Vec<Instance>, Error> {
    let resp = client
        .describe_instances()
        .set_instance_ids(Some(instance_ids))
        .send()
        .await?;

    let mut instances = Vec::new();

    for reservation in resp.reservations().unwrap() {
        let mut v = reservation
            .instances
            .clone()
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect();
        instances.append(&mut v);
    }

    Ok(instances)
}

async fn get_secret(
    client: &aws_sdk_secretsmanager::Client,
    name: &str,
) -> Result<DbCredentials, Error> {
    let resp = client.get_secret_value().secret_id(name).send().await?;

    let credentials: DbCredentials = serde_json::from_str(resp.secret_string().unwrap())?;
    Ok(credentials)
}

// This is the main body for the function.
async fn function_handler(_event: LambdaEvent<CloudWatchEvent>) -> Result<(), Error> {
    let config = Config::init_from_env().unwrap();
    let aws_shared_config = aws_config::load_from_env().await;

    let client_elbv2 = aws_sdk_elasticloadbalancingv2::Client::new(&aws_shared_config);
    let client_ec2 = aws_sdk_ec2::Client::new(&aws_shared_config);
    let client_secretsmanager = aws_sdk_secretsmanager::Client::new(&aws_shared_config);

    info!(
        "Getting unhealthy instances from target group {}",
        config.target_group_arn
    );
    let instance_ids =
        get_unhealthy_instances_from_target_group(&client_elbv2, &config.target_group_arn).await?;

    if !instance_ids.is_empty() {
        let instances = get_instances_from_instance_ids(&client_ec2, instance_ids).await?;

        info!(
            "Getting database configuration from Secret Manager's secret {}",
            &config.secret_id
        );
        let db_config = get_secret(&client_secretsmanager, &config.secret_id).await?;

        let opts = OptsBuilder::new()
            .user(Some(db_config.user))
            .pass(Some(db_config.password))
            .ip_or_hostname(Some(&db_config.host))
            .tcp_port(db_config.port);

        let mut conn = Conn::new(opts)?;

        info!(
            "Querying processes from MySQL at {}:{}",
            db_config.host, db_config.port
        );

        let processes = conn.query_map(
            // query processes with remote hosts in current state for less than QUERY_TIMEOUT
            format!("SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST WHERE HOST != '' AND HOST != 'localhost' AND TIME < {};", config.query_timeout),
            |mut row: Row| Process {
                id: row.take("ID").unwrap(),
                user: row.take("USER").unwrap(),
                host: row.take("HOST").unwrap(),
                db: row.take("DB").unwrap(),
                command: row.take("COMMAND").unwrap(),
                time: row.take("TIME").unwrap(),
                state: row.take("STATE").unwrap(),
                info: row.take("INFO").unwrap(),
            },
        )?;

        let mut instance_ids_to_terminate = Vec::new();

        for instance in instances {
            // match instances' IPs with processes.
            let matching_processes: Vec<&Process> = processes
                .iter()
                .filter(|process| process.host.is_some())
                .filter(|process| process.host.as_ref().unwrap().contains(&instance.ip))
                .collect();

            // If we did not match a running process it means that the instance is really unhealthy and not just blocking on database access.
            if matching_processes.is_empty() {
                instance_ids_to_terminate.push(instance.id);
            }
        }

        info!("Terminating instances: {:#?}", instance_ids_to_terminate);
        let _ = client_ec2
            .terminate_instances()
            .set_instance_ids(Some(instance_ids_to_terminate))
            .send()
            .await?;
    } else {
        info!(
            "No unhealthy instances found in target group {}",
            config.target_group_arn
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config = Config::init_from_env().unwrap();

    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    run(service_fn(function_handler)).await
}
