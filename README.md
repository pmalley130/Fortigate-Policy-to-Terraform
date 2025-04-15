# Fortigate-Policy-to-Terraform
Scripts to convert a Fortigate firewall policy to Network Security Groups. Several assumptions are made:
- The original policy has a destination in the cloud, so only ingress is handled (egress stays as allow all,)
- The firewall policy is only for one VPC
- No IPv6 involvement
- Region is set by environment

## To-do
- check all CIDRs for VPCs and created separate sgs instead of checking for first one
- logic to handle any/all object in source/destination of rule
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