from dotenv import load_dotenv
import boto3
import ipaddress

#function to search all VPCs for a CIDR and return the VPCid of a match
def findAWSVPCbyCIDR(inputCIDR):
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
    return None #if no VPCs match then return None