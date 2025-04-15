from helpers.classes import Policy
from helpers.cloud import findAWSVPCbyCIDR
from helpers.terraform import generateAWSsecurityGroup

policyName = input("Enter the name of the firewall policy: ") #ask for policy name for use in API call
policy = Policy(policyName) #create said policy

outputFile = f"{policy.name}.tf.json" #set default output to a <policy name>.tf.json
print(f"File will be written to {outputFile}")

outputConsole = input("Would you like to write to console instead? (y/n)")

if outputConsole.lower() == "y": #if user enters Y then set to none so we print instead
    outputFile = None
for destination in policy.getDestinations(): #step through destinations until we find a VPC that matches, then break
    vpc = findAWSVPCbyCIDR(destination)
    if vpc:
        break

if not vpc:
        print("No matching VPC found - terraform will still generate but vpc ID will be 'none'")
generateAWSsecurityGroup(policy, vpc, outputFile)