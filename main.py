from helpers.classes import Policy
from helpers.cloud import findVPCbyCIDR
from helpers.creation import generateTF

policyName = input("Enter the name of the firewall policy: ") #ask for policy name for use in API call
policy = Policy(policyName) #create said policy

outputFile = f"{policy.name}.tf.json" #set default output to a <policy name>.tf.json
print(f"File will be written to {outputFile}")

outputConsole = input("Would you like to write to console instead? (y/n)")

if outputConsole.lower() == "y": #if user enters Y then set to none so we print instead
    outputFile = None

#build list of VPCs that we need to make security groups for
VPCs = [] 
for destination in policy.getDestinations():
    vpc = findVPCbyCIDR(destination)
    if vpc and vpc not in VPCs: #add VPC to list if found and not already in list
        VPCs.append(vpc)
if not VPCs:
        print("No matching VPC found - terraform will still generate but vpc ID will be 'none'")

generateTF(policy, VPCs, outputFile) #make the TF