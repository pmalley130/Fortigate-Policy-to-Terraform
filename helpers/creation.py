from helpers.classes import Policy, Service

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
    
    return ingressRules, egressRules

def createAWSbyCLI(
        policy: Policy,
        output_file = None
):
    pass

def createAWSbyAPI(
        policy: Policy,
        writeOut = None,
):
    import boto3 #package for AWS API
    from helpers.cloud import findVPCbyCIDR, getVPCName #needed so rule CIDRs only match their VPC
    
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
    from helpers.cloud import findVPCbyCIDR, getVPCName #needed so rule CIDRs only match their VPC
    #initialize terraform config
    import terrascript
    import terrascript.provider as provider
    import terrascript.resource as resource
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
