# Fortigate-Policy-to-Terraform
Scripts to convert a Fortigate firewall policy to Network Security Groups. Assumes that the fortigate is on-prem, and the NSG will need to match.

Unfinished

## To-do
- find VPC using AWS SDK boto3
- output Terraform files
- support policy json file as argument
- support IPv6
- support other cloud providers

## Dependencies
```
boto3
fortigate-api
```