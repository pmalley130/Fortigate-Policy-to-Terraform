from helpers.classes import Policy


def generateAWS_CLI(
        policy: Policy,
        output_file = None
):
    pass
'''
    import json

    from helpers.cloud import getVPCName

    bash = [ #start bash file with shebang and nl
        "#!/usr/bin/env bash",
        "",
    ]

    ingressRules, egressRules = createRules(policy, "cli") #make ingress and egress rules in the format needed for bash

    for vpc in policy.VPCs:
        vpcName = getVPCName(vpc) #we want unique sg names, so append the vpcID to the policy name (or use the VPCid if no name)
        if vpcName:
            sg_name = f"{policy.name}_{vpcName}"
        else:
            sg_name = f"{policy.name}_{vpc}"

        description = f"Security group for policy {policy.name}, built from firewall"

        bash += [ #add the lines needed for the bash script - first we make the security group so it can be referenced in actual rules
            f'#SECURITY GROUP CONFIGURATION FOR {vpcName}', #set the variables
            f'GROUP_NAME="{sg_name}"',
            f'DESCRIPTION="{description}"',
            f'VPC_ID="{vpc}"',
            f'FIREWALL_POLICY_NAME="{policy.name}"',
            "",
            f'#Check for existing security group {sg_name}, if exists, save to id GROUP_ID', #check for existing sg
            'GROUP_ID=$(aws ec2 describe-security-groups \\',
            '  --filters Name=group-name,Values="$GROUP_NAME" Name=vpc-id,Values="$VPC_ID" \\',
            '  --query "SecurityGroups[0].GroupId" \\',
            '  --output text)',
            "",
            'if [[ "$GROUP_ID" == "None" ]]; then', #if sg exists..
            f'  #Security group {sg_name} not found in {vpc}, so creating and tagging one',
            f'  echo "Creating security group for {vpc}"', #make the group
            '  GROUP_ID=$(aws ec2 create-security-group \\',
            '    --group-name "$GROUP_NAME" \\',
            '    --description "$DESCRIPTION" \\',
            '    --vpc-id "$VPC_ID" \\',
            "    --query 'GroupId' \\",
            '    --output text)',
            "",
            '  #Tag new group',
            '  echo "Tagging new security group "$GROUP_ID"..."', #tag the group
            '  aws ec2 create-tags \\',
            '    --resources "$GROUP_ID" \\',
            '    --tags Key=firewall_policy:name,Value="$FIREWALL_POLICY_NAME"',
            "else",
            f'  echo "Found security group {sg_name} in {vpc} with ID: $GROUP_ID"', #state that group exists
            'fi',
            "",
            'echo "adding ingress rules"'
        ]

        for rule in ingressRules:
            ipRanges = [{"CidrIp":cidr, "Description":rule["description"]} for cidr in rule["cidrs"]] #generate the rules
            ipPermission = {
                "IpProtocol":rule["protocol"],
                "FromPort":rule["from_port"],
                "ToPort":rule["to_port"],
                "IpRanges":ipRanges
            }
            ipPermissionJSON = json.dumps([ipPermission]) #--ipPermission needs a json object, so explode it
            bash += [
                "",
                f'#Rules for {rule["description"]}',
                '#pipe the output to see how many rules are created - full output is way too large',
                f'echo "Creating rules for {rule["description"]}"', #apply the rules
                'SG_OUT=$(aws ec2 authorize-security-group-ingress \\',
                '  --group-id "$GROUP_ID" \\',
                f"  --ip-permissions '{ipPermissionJSON}' \\",
                "  --query 'SecurityGroupRules | length(@)' \\",
                '  --output text)',
                'echo "$SG_OUT rules created"'
            ]

        #bash += [ can't remake egress allow all if it already exists
        #    "",
        #    'echo "allowing all egress.."',
        #    'aws ec2 authorize-security-group-egress \\',
        #    '  --group-id "$GROUP_ID" \\',
        #    '  --protocol -1 \\',
        #    '  --cidr 0.0.0.0/0 \\',
        #]

        bash += [""]


    if output_file:
        with open(output_file, "w", newline="\n") as f: #write the bash script
            f.write("\n".join(bash))
    else:
        print('\n'.join(bash)) #print every line on new line
'''
def createAWSbyAPI(SG_JSON):
    import boto3  #package for AWS API
    import botocore.exceptions

    ec2 = boto3.client('ec2') #create connection to AWS

    for sg in SG_JSON: #step through security groups
            try:
                existing_SGs = ec2.describe_security_groups( #grab any existing SGs with this name in this VPC
                    Filters = [
                        {'Name': 'group-name', 'Values': [sg['GroupName']]},
                        {'Name': 'vpc-id', 'Values': [sg['VpcId']]}
                    ]
                )

                if existing_SGs['SecurityGroups']: #if any of the existing ones match what we're about to make
                    sgID = existing_SGs['SecurityGroups'][0]['GroupId'] # reuse the ID
                    print(f"Re-using existing security group {sg['GroupName']} with ID {sgID} for {sg['VpcId']}")
                else: #otherwise make a new SG
                    response = ec2.create_security_group(
                        GroupName=sg['GroupName'],
                        Description=sg['Description'],
                        VpcId=sg['VpcId'],
                        TagSpecifications=[{
                            'ResourceType': 'security-group',
                            'Tags': sg['Tags']
                        }]
                    )

                sgID = response['GroupId'] #save the new SG ID and let the console know
                print(f"Created security group {sg['GroupName']} as {sgID}")

                #add ingress rules to SG
                ingressResponse = ec2.authorize_security_group_ingress(
                    GroupId=sgID,
                    IpPermissions=sg['IpPermissions']
                )

                if ingressResponse.get('Return',False): #if we didn't get any errors
                    print(f"Added {len(sg['IpPermissions'])} ingress rules to {sgID}")
                else:
                    print(f"No rules were added to SG {sgID} — possibly already present")

            except botocore.exceptions.ClientError as e: #if we raised some exceptions
                if 'InvalidPermission.Duplicate' in str(e):
                    print(f"Some or all rules already exist in SG {sg['GroupName']}")
                else:
                    print(f"Error processing SG {sg['GroupName']}: {e}")

'''
def generateAWS_TF(
    policy: Policy,
    output_file = None
):
    import terrascript
    from terrascript import resource

    from helpers.cloud import getVPCName  #needed so rule CIDRs only match their VPC
    config = terrascript.Terrascript()

    ingressRules, egressRules = createRules(policy, "tf") #no matter the VPC the source rules will be the same so make them before the loop

    for vpc in policy.VPCs:
        vpcName = getVPCName(vpc) #terrascript requires unique sg names, so append the vpcID to the policy name (or use the VPCid if no name)
        if vpcName:
            sg_name = f"{policy.name}_{vpcName}"
        else:
            sg_name = f"{policy.name}_{vpc}"

        sg = resource.aws_security_group( #build security group
            sg_name,
            name = policy.name,
            description = f"Security group for policy {policy.name}, built from firewall",
            vpc_id = vpc,
            ingress = ingressRules,
            egress = egressRules,
            tags = {"firewall_policy": policy.name}
        )

        config += sg #add security group to file

    if output_file: #if we've designated a file name write to it, otherwise print config to console
        with open(output_file, "w") as f:
            f.write(str(config))
    else:
        print(str(config))
'''
