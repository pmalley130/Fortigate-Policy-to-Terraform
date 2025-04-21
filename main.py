from helpers.classes import Policy
from helpers.creation import createAWSbyAPI, generateAWS_CLI, generateAWS_TF

policyName = input("Enter the name of the firewall policy: ") #ask for policy name for use in API call
policy = Policy(policyName) #create said policy

outputConsole = input("Would you like to write security group(s) JSON to console first? (y/n)")

if outputConsole.lower() == "y": #if user enters Y then set to none so we print instead
        import json
        outputFile = print(json.dumps(policy.SG_JSON,indent=5))

choice = input("Choose your method: \n 1. Generate Terraform JSON \n 2. Create by AWS API\n 3. Generate Bash script\n")

match choice:
    case "1":
          generateAWS_TF(policy.SG_JSON)
    case "2":
          createAWSbyAPI(policy.SG_JSON)
    case "3":
          generateAWS_CLI(policy.SG_JSON)
