from helpers.classes import Policy
from helpers.creation import createAWSbyAPI, generateAWS_CLI, generateAWS_TF

policyName = input("Enter the name of the firewall policy: ") #ask for policy name for use in API call
policy = Policy(policyName) #create said policy

choice = input("Choose your method: \n 1. Generate Terraform JSON \n 2. Create by AWS API\n 3. Generate Bash script\n")

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

def choseCLI(policy):
    outputFile = f"{policy.name}.sh" #set default output to a <policy name>.tf.json
    print(f"File will be written to {outputFile}")

    outputConsole = input("Would you like to write to console instead? (y/n)")

    if outputConsole.lower() == "y": #if user enters Y then set to none so we print instead
        outputFile = None

    generateAWS_CLI(policy, outputFile)

match choice:
    case "1":
          choseTF(policy)
    case "2":
          choseAPI(policy)
    case "3":
          choseCLI(policy)
