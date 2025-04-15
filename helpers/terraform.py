import terrascript
import terrascript.provider as provider
import terrascript.resource as resource
from helpers.classes import Policy, Service

def generate_AWS_security_group(
    policy: Policy,
    region = "us-east-1",
    vpc = None,
    output_file = None
):
    #initialize terraform config
    config = terrascript.Terrascript()
    config += provider.aws(region=region)

    ingressRules = [] #empty list to put service objects into
    for svc in policy.getServices(): #step through each service in the policy and add it to security group
        ingressRules.append({
            "from_port" : svc.from_port,
            "to_port": svc.to_port,
            "protocol": svc.ip_protocol,
            "cidr_blocks": policy.getSources(),
            "description": f"{svc.name}"
        })

    egressRules = [{ #assume egressRules always allow all out since it's stateful
        "from_port": 0,
        "to_port": 0,
        "protocol": "-1",
        "cidr_blocks": "0.0.0.0/0"
    }]

    sg = resource.aws_security_group( #build security group
        policy.name,
        name = policy.name,
        description = f"Security group for policy {policy.name}, built from firewall",
        vpc_id = vpc,
        ingress = ingressRules,
        egress = egressRules,
        tags = {"Name": policy.name}
    )

    config += sg #add security group to file

    if output_file: #if we've designated a file name write to it, otherwise print config to console
        with open(output_file, "w") as f:
            f.write(str(config))
    else:
        print(str(config))
