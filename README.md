# Database Migration Aware Health Check Lambda

Use Lambda to clarify ambiguous health check status during database migrations.

## Disclaimer

The solution implemented by this function is not well-architected.

It implements a demonstration of a workaround for a very specific issue, in a context where implementing application modernization is not feasible.

## Problem statement

> We cannot use ALB HTTP health checks to recover failed instances with Application Auto Scaling as those may return false-negatives during a database migration given our application code. We cannot make any change to existing application code.

## Solution

> Apply ALB health checks (terminate) after making sure that instances are not actively using the database.

This Lambda function :
- lists unhealthy instances from a target group
- checks if those instances are running queries on an Aurora Mysql writer instance
- terminates instances that are determined to be effectively unhealthy

## Requirements

### Networking

This function should be executed with private VPC networking (to be able to access the Aurora endpoint) with NAT Gateway or NAT instance Internet access (to call service APIs).
An alternative to NAT Internet access is to setup VPC endpoints for : EC2, Elastic Load Balancing, Cloudwatch Logs, Secrets Manager.

The function should be allowed to connect to the Aurora's writer instance Security Group.

### Secret

This function requires access to an AWS Secrets Manager secret with the following format:

```json
{
    "user":"xxxxxxx",
    "password":"yyyyyy",
    "host":"xxxxxx.cluster-yyyyyy.region.rds.amazonaws.com",
    "port":3306
}
```

### IAM permissions

Required on top of default Lambda permissions, `ec2` and `elasticloadbalancing` should be further restricted :

```json
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "describe and terminate",
			"Effect": "Allow",
			"Action": [
				"ec2:DescribeInstances",
				"ec2:TerminateInstances",
				"elasticloadbalancing:DescribeTargetHealth"
			],
			"Resource": "*"
		},
		{
			"Sid": "get secret",
			"Effect": "Allow",
			"Action": "secretsmanager:GetSecretValue",
			"Resource": "arn:aws:secretsmanager:region:account:secret:id"
		}
	]
}
```

## Configuration
Through environment variables:

- `TARGET_GROUP_ARN`: arn of the target group that will be monitored.
- `SECRET_ID`: secret where database credentials are stored.
- `QUERY_TIMEOUT`: time after which an ongoing database query does not make an instance healthy.
- `LOG_LEVEL`: one of `debug`, `info`, `warn`, `error`.


## Build

```shell
# install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# install cargo lambda (MacOS)
brew tap cargo-lambda/cargo-lambda
brew install cargo-lambda

# install cargo lambda (Linux)
pip3 install cargo-lambda

# build for AWS Lambda powered by Graviton2
cargo lambda build --release --arm64 --output-format zip

# find the package
ls target/lambda/*/bootstrap.zip
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
