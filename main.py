from helpers.classes import Policy
from helpers.cloud import findVPCbyCIDR
from helpers.creation import generateAWS_TF, createAWSbyAPI

policyName = input("Enter the name of the firewall policy: ") #ask for policy name for use in API call
policy = Policy(policyName) #create said policy

choice = input(f"Choose your method: \n 1. Generate Terraform JSON \n 2. Create by AWS API\n") 

#define methods used by choices
def choseTF(policy):
    outputFile = f"{policy.name}.tf.json" #set default output to a <policy name>.tf.json
    print(f"File will be written to {outputFile}")

    outputConsole = input("Would you like to write to console instead? (y/n)")

    if outputConsole.lower() == "y": #if user enters Y then set to none so we print instead
        outputFile = None

    generateAWS_TF(policy, outputFile) #make the TF

def choseAPI(policy):
    outputConsole = input("Confirming this will CREATE OBJECTS. y for proceed, n will print sample output. (y/n)")

    if outputConsole.lower() == "y": #if user enters Y then set to none so we print instead
        writeOut = None
    else:
         writeOut = outputConsole
         
    createAWSbyAPI(policy, writeOut)

match choice:
    case "1":
          choseTF(policy)
    case "2":
          choseAPI(policy)