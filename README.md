#Fortigate-Policy-to-Terraform
Scripts to convert a Fortigate firewall policy to Network Security Groups. Assumes that the fortigate is on-prem, and the NSG will need to match.

Unfinished

##To-do
- Handle nested groups in source or destination
- make getService to return protocols used in policy
- find VPC using AWS SDK boto3
- output Terraform files
- support IPv6
- support other cloud providers