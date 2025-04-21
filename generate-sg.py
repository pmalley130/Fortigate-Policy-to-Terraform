import argparse
import json

from helpers.classes import Policy
from helpers.creation import createAWSbyAPI, generateAWS_CLI, generateAWS_TF


def main():
      #set up positional arguments
      parser = argparse.ArgumentParser(
        description="Generate or deploy AWS security groups from firewall policy."
      )
      parser.add_argument( #name of the policy
        "policyName",
        nargs="?",
        help="Name of the firewall policy."
      )
      parser.add_argument( #chose how to generate the security groups
        "method",
        nargs="?",
        choices=["TF", "API", "CLI"],
        help="Deployment method: TF (Terraform), API (AWS API), CLI (Bash script)."
      )
      parser.add_argument( #whether to print json to console
        "--print-json",
        action="store_true",
        help="Print security group JSON to the console."
      )

      args = parser.parse_args()

      #use argument if provided, otherwise run interactive
      policyName = args.policyName or input("Enter the name of the firewall policy: ")
      policy = Policy(policyName)

      #if print-json is set and no generation method passed just print and exit
      if args.print_json and not args.method:
            print(json.dumps(policy.SG_JSON,indent=2))
            return

      #otherwise print if requested and proceed
      if args.print_json:
            print(json.dumps(policy.SG_JSON,indent=2))

      method = args.method
      if not method:
            print("Choose your method:\n 1. Generate Terraform JSON\n 2. Create by AWS API\n 3. Generate Bash script")
            method = input("Enter TF, API, or CLI: ").upper()

      match method:
            case "TF":
                  generateAWS_TF(policy.SG_JSON)
            case "API":
                  createAWSbyAPI(policy.SG_JSON)
            case "CLI":
                  generateAWS_CLI(policy.SG_JSON)
            case _:
                  print("Invalid generation method. Choose from TF, API, or CLI.")

if __name__ == "__main__":
    main()
