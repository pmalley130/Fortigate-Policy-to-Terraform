# Fortigate-Policy-to-Terraform
Scripts to convert a Fortigate firewall policy to Network Security Groups. Several assumptions are made:
- The original policy has a destination in the cloud, so only ingress is handled (egress stays as allow all)
- security groups are attached at the VPC level
  - in the future I may scan "destinations" in the firewall policy to determine if the destination is a /32 and therefore attach at the EC2/instance level instead
- No IPv6 involvement
- Region is set by environment

## Usage
- Run "python main.py" and follow the prompts.
  - Bash and Terraform options generate files (using the fw policy name) used to create the security groups
  - API option directly creates the security groups


## To-do
- take arguments in main for creation type (-tf; -api; -cli, policy name)
- logic to handle any/all object in source/destination of rule
- support creating SG for instances OR VPC
- get egress rule from vpc and copy/recreate them instead of defaulting to allow all
- if no environment, ask for missing details at runtime
- support policy json file as argument
- support IPv6
- support other cloud providers

## Dependencies
```
boto3
fortigate-api
terrascript
```