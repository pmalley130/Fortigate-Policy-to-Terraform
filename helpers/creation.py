from helpers.classes import Policy


def createRules(policy, type): #create inbound and outbound rules to attach to security group
    ingressRules = [] #empty list to put service objects into

    match type: # of course TF, CLI, and boto3 all have different formatting issues
        case "tf": #for terraform
            for svc in policy.getServices(): #step through each service in the policy and add it to security group
                ingressRules.append({
                    "from_port" : svc.from_port,
                    "to_port": svc.to_port,
                    "protocol": svc.ip_protocol,
                    "cidr_blocks": policy.getSources(),
                    "ipv6_cidr_blocks": [],
                    "prefix_list_ids": [],
                    "security_groups": [],
                    "self" : "false",
                    "description": f"{svc.name}"
                })

                egressRules = [{ #assume egressRules always allow all out since it's stateful
                    "from_port": "0",
                    "to_port": "0",
                    "protocol": "-1",
                    "cidr_blocks": ["0.0.0.0/0"],
                    "ipv6_cidr_blocks": [],
                    "prefix_list_ids": [],
                    "security_groups": [],
                    "self" : "false",
                    "description": f"{svc.name}"
                }]

        case "api": #for boto3
            for svc in policy.getServices(): #step through each service in the policy and add it to security group
                rangeList = [] #empty list to add source objects to
                for source in policy.getSources(): #each CIDR block needs its own description
                    rangeList.append({
                        'CidrIp': source,
                        'Description': svc.name
                    })

                ingressRules.append({
                    "FromPort" : svc.from_port,
                    "ToPort": svc.to_port,
                    "IpProtocol": svc.ip_protocol,
                    "IpRanges": rangeList,
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                })

                egressRules = [{ #assume egressRules always allow all out since it's stateful
                    "FromPort": 0,
                    "ToPort": 0,
                    "IpProtocol": "-1",
                    "IpRanges": [{'CidrIp' : "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                }]

        case "cli": #for cli
            ingressRules = []
            for svc in policy.getServices():
                ingressRules.append({
                    "from_port":svc.from_port,
                    "to_port":svc.to_port,
                    "protocol":svc.ip_protocol,
                    "cidrs":policy.getSources(),
                    "description":f"{svc.name}"
                })
            egressRules = []

    return ingressRules, egressRules

def generateAWS_CLI(
        policy: Policy,
        output_file = None
):
    import json

    from helpers.cloud import getVPCName

    bash = [ #start bash file with shebang and nl
        "#!/usr/bin/env bash",
        "",
        "#NOTE: Due to CLI limitations, ingress rules created in this method cannot have descriptions.",
        "#Instead, descriptions will be in the bash file for documentation",
        "#Using TF or API will allow for descriptions viewable in the AWS Web Gui",
        ""
    ]

    ingressRules, egressRules = createRules(policy, "cli") #make ingress and egress rules in the format needed for bash

    for vpc in policy.VPCs:
        vpcName = getVPCName(vpc) #we want unique sg names, so append the vpcID to the policy name (or use the VPCid if no name)
        if vpcName:
            sg_name = f"{policy.name}_{vpcName}"
        else:
            sg_name = f"{policy.name}_{vpc}"

        description = f"Security group for policy {policy.name}, built from firewall"

        bash += [ #add the lines needed for the bash script - first we make the security group so it can be referenced in actual rule
            f'#SECURITY GROUP CONFIGURATION FOR {vpcName}',
            f'GROUP_NAME="{sg_name}"',
            f'DESCRIPTION="{description}"',
            f'VPC_ID="{vpc}"',
            f'FIREWALL_POLICY_NAME="{policy.name}"',
            "",
            f'echo "Creating security group for {vpc}"',
            'GROUP_ID=$(aws ec2 create-security-group \\',
            '  --group-name "$GROUP_NAME" \\',
            '  --description "$DESCRIPTION" \\',
            '  --vpc-id "$VPC_ID" \\',
            "  --query 'GroupId' \\",
            '  --output text)',
            "",
            'echo "Tagging new security group "$GROUP_ID"..."',
            'aws ec2 create-tags \\',
            '  --resources "$GROUP_ID" \\',
            '  --tags Key=firewall_policy:name,Value="$FIREWALL_POLICY_NAME"',
            "",
            'echo "adding ingress rules"'
        ]

        for rule in ingressRules:
            ipRanges = [{"CidrIp":cidr, "Description":rule["description"]} for cidr in rule["cidrs"]]
            ipPermission = {
                "IpProtocol":rule["protocol"],
                "FromPort":rule["from_port"],
                "ToPort":rule["to_port"],
                "IpRanges":ipRanges
            }
            ipPermissionJSON = json.dumps([ipPermission])
            bash += [
                "",
                f'#Rule for {rule["description"]}',
                'aws ec2 authorize-security-group-ingress \\',
                '  --group-id "$GROUP_ID" \\',
                f"  --ip-permissions '{ipPermissionJSON}' \\",
                "  --query 'SecurityGroupRules[*].SecurityGroupRuleId' \\",
                '  --output text'
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


    with open("scripttest.sh", "w", newline="\n") as f: #write the bash script
        f.write("\n".join(bash))

def createAWSbyAPI(
        policy: Policy,
        writeOut = None,
):
    import boto3  #package for AWS API

    from helpers.cloud import getVPCName  #needed so rule CIDRs only match their VPC

    ec2 = boto3.client('ec2')

    ingressRules, egressRules = createRules(policy, "api") #no matter the VPC the source rules will be the same so make them before the loop

    for vpc in policy.VPCs: #step through VPCs identified for rule
        vpcName = getVPCName(vpc) #we want unique sg names, so append the vpcID to the policy name (or use the VPCid if no name)
        if vpcName:
            sg_name = f"{policy.name}_{vpcName}"
        else:
            sg_name = f"{policy.name}_{vpc}"

        if not writeOut:
            response = ec2.create_security_group( #create new security group to place rules in based on VPC
                GroupName = sg_name,
                Description = f"Security group for policy {policy.name}, built from firewall",
                VpcId = vpc,
                TagSpecifications=[
                    {
                        'ResourceType':'security-group',
                        'Tags': [
                            {
                                'Key':'firewall_policy',
                                'Value': policy.name
                            }
                        ]
                    }
                ]
            )

            SGid = response['GroupId'] #get the sg ID now that it's created, for use in attaching rule set
            print(f"Created new Security Group {SGid} with name {sg_name}")
            ec2.authorize_security_group_ingress(
                GroupId = SGid,
                IpPermissions = ingressRules
            )

            #can't duplicate egress rules, default allow all exists - keeping it here for later functionality
            #ec2.authorize_security_group_egress(
            #    GroupId = SGid,
            #    IpPermissions = egressRules
            #)

        if writeOut:
            import json
            print(f"Printing simulated output for NEW security group {sg_name}")
            print(f"Ingress rules: {json.dumps(ingressRules, indent=5)}")
            print(f"Egress rules {json.dumps(ingressRules, indent=5)}")


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
