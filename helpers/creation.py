from helpers.classes import Policy, Service

def createAWSbyAPI(
        policy: Policy,
        vpc = None,
        output_fule = None,
):
    pass

def createAWSbyCLI(
        policy: Policy,
        vpc = None,
        output_file = None
):
    pass

def generateTF(
    policy: Policy,
    VPCs = [],
    output_file = None
):
    from helpers.cloud import findVPCbyCIDR, getVPCName #needed so rule CIDRs only match their VPC
    #initialize terraform config
    import terrascript
    import terrascript.provider as provider
    import terrascript.resource as resource
    config = terrascript.Terrascript()

    for vpc in VPCs:
        ingressRules = [] #empty list to put service objects into
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
