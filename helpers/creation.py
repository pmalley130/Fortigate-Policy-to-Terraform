def generateAWS_CLI(SG_JSON, scriptPath="create_SGs.sh"):
    import json

    bash = [ #start bash file with shebang error settings
        "#!/usr/bin/env bash",
        "",
        "set -euo pipefail",
    ]

    rulesFile = "IpPermissions.json"

    for i, sg in enumerate(SG_JSON):
        groupName = sg['GroupName']
        description = sg['Description'].replace('"','\\".')
        vpcID = sg['VpcId']

        #AWS CLI is particular about passing tag specifications so we do some weird stuff here
        tagSpecs = formatTagSpecifications(sg['Tags'])

        if i == 0:
             #Write rules JSON file, reused in each SG so write once
            rulesData = {"IpPermissions": sg['IpPermissions']}
            with open(rulesFile, 'w') as rf:
                json.dump(rulesData, rf, indent=2)
            print(f"Ingress rules JSON written to {rulesFile}")


        bash += [
            f"echo \"Processing security group {groupName}\"",
            "SG_ID=$(aws ec2 describe-security-groups \\", #attempt to find existing security group
            f"--filters Name=group-name,Values={groupName} Name=vpc-id,Values={vpcID} \\",
            "--query 'SecurityGroups[0].GroupId' --output text || true)",
            "",
            "if [ \"$SG_ID\" == \"None\" ] || [ -z \"$SG_ID\" ]; then", #if we don't find the  group
            f"  echo \"Creating security group {groupName}\"",
            "  SG_ID=$(aws ec2 create-security-group \\", #create new group
            f"--group-name \"{groupName}\" \\",
            f"--description \"{description}\" \\",
            f"--vpc-id {vpcID} \\",
            f"--tag-specifications {tagSpecs} \\",
            "--query 'GroupId' --output text)",
            "else",
            f"  echo \"Re-using existing security group {groupName} (ID: $SG_ID)\"",#otherwise re-use existing
            "fi",
            "",
            "echo \"Attaching ingress rules to $SG_ID\"", #attach rules file to new SG
            "RESPONSE=$(aws ec2 authorize-security-group-ingress \\",
            "--group-id $SG_ID \\",
            f"--cli-input-json file://{rulesFile})",
            "",
            "if [[ $? -eq 0 ]]; then",
            '  RULE_COUNT=$(echo "$RESPONSE" | jq \'.SecurityGroupRules | length\')',
            f'  echo "Successfully created $RULE_COUNT rule(s) for {groupName}"',
            'else',
            f'  echo "Warning: Could not add rules to {groupName}"',
            '  echo "$RESPONSE"',
            'fi',
            ""
        ]

    bash.append("echo \"All groups processed.\"")

    #write script to file
    with open(scriptPath, 'w', newline="\n") as f:
        f.write("\n".join(bash))

    print(f"Bash script written to {scriptPath}")

def formatTagSpecifications(tags): #for use in CLI
    tagParts = [f"{{Key={tag['Key']},Value={tag['Value']}}}" for tag in tags]
    tagString = f"'ResourceType=security-group,Tags=[{','.join(tagParts)}]'"
    return tagString

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
