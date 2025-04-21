# AWS Security Group Generator

This script generates or deploys AWS Security Groups based on a named Fortigate Firewall Policy. You can use it to:
- Generate Terraform JSON (`TF`)
- Deploy Security Groups via the AWS API (`API`)
- Generate Bash CLI script (`CLI`)
  - The CLI option also generates an "IpPermissions.json" file that must be in the same folder as the generated script when it is ran.   
- Optionally print the generated JSON to the console

Several assumptions are made:
- The original policy has a destination in the cloud, so only ingress is handled (egress stays as allow all)
- security groups are attached at the VPC level
  - in the future I may scan "destinations" in the firewall policy to determine if the destination is a /32 and therefore attach at the EC2/instance level instead
- No IPv6 involvement
- Region is set by environment

## Usage
`python generate_sg.py [policy_name] [method] [--print-json]`

### Arguments
| Argument  | Type | Description |
| :------------- |:-------------|:-------------
| `policy_name`      | string   | (Required) Name of the firewall policy to convert. |
| `method`     | string     | (Optional) Deployment method: `TF`, `API`, or `CLI`.
| `--print-json`   | flag    | (Optional) Print the generated security group JSON to the console.

### Examples
1. Generate Terraform JSON and print the result
```
python generate_sg.py MyPolicy TF --print-json
```
2. Deploy security groups using the AWS API
```
python generate_sg.py MyPolicy API
```
3. Only print the JSON
```
python generate_sg.py MyPolicy --print-json
```
4. Run in fully interactive mode (follow the prompts)
```
python generate_sg.py
```
## Dependencies
```
boto3
fortigate-api
terrascript
jq (if running CLI option)
```
## To-do
- logic to handle any/all object in source/destination of rule
- support creating SG for instances OR VPC
- get egress rule from vpc and copy/recreate them instead of defaulting to allow all
- if no environment, ask for missing details at runtime
- support policy json file as argument
- support IPv6
- support other cloud providers

