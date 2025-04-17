from dotenv import load_dotenv
import ipaddress

#function to search all VPCs for a CIDR and return the VPCid of a match
def findVPCbyCIDR(inputCIDR):
    import boto3
    load_dotenv() #needed for reading AWS creds from environment file

    #convert CIDR str to network object
    try:
        inputNetwork = ipaddress.ip_network(inputCIDR)
    except ValueError as e:
        print(f"Invalid CIDR range: {e}")
        return
    
    ec2 = boto3.client('ec2') #build connection to AWS
    response = ec2.describe_vpcs() #get all VPCs
    for vpc in response['Vpcs']: #step through VPCs
        vpcCIDRBlocks = vpc.get('CidrBlockAssociationSet', []) #get list of CIDRs associated with this VPC
        for CIDR in vpcCIDRBlocks: #step through each CIDR associated with this VPC
            vpcCIDR = CIDR['CidrBlock'] #get the str from the AWS data
            try:
                vpcNetwork = ipaddress.ip_network(vpcCIDR) #convert CIDR str to network object
                if inputNetwork.subnet_of(vpcNetwork): #if the input CIDR is contained within the CIDR of this vpc return the VPC ID
                    return vpc['VpcId']
            except ValueError:
                continue

#function to search all VPCs by ID and to get the name tag
def getVPCName(vpcID):
    import boto3
    load_dotenv() #needed for reading AWS creds from environment file
    
    ec2 = boto3.client('ec2') #build connection to aws
    response = ec2.describe_vpcs(VpcIds=[vpcID]) #only grab the VPC we want
    VPCs = response.get("Vpcs", []) #only search through the info we want

    for tag in VPCs[0].get("Tags", []): #grab the tags and look for name
        if tag["Key"] == "Name":
            return tag["Value"]