#todo - handle groups, get services

import fortigate_api
from helpers import loadAPI
import ipaddress

class Policy:
    def __init__(self, policyName):
        api = loadAPI.createAPI()
        api_results = api.cmdb.firewall.policy.get(filter=f'"name=={policyName}"') #make API call for policy by name
        if api_results: #if not empty, assign the needed variables to the first API result
            first = api_results[0]
            self.name = first.get('name')
            self.dstaddr = first.get('dstaddr')
            self.srcaddr = first.get('srcaddr')
            self.service = first.get('service')
            self.comments = first.get('comments')
        else:
            raise ValueError ("No policies from API")

    def __str__(self):
        return self.name

    def getSources(self):
        api = loadAPI.createAPI()

        sourceNames = list(self.srcaddr) #get source address objects from policy
        sourceCIDRS = list() #create an empty list for CIDRs

        for source in sourceNames: #walk through sources from policy and add address objects
            addressObj = api.cmdb.firewall.address.get(name=(source["name"]))
            
            if addressObj[0].get('type') == 'ipmask': #if it's a subnet or individual host
                addressRaw = addressObj[0].get("subnet") #pull the ip info from the object
                ip, netmask = addressRaw.split() #it's always one string, formatted [<ip address> <subnetmask>] so instead of regex we can just use split to assign ip and netmask
                network = ipaddress.IPv4Network(ip, netmask) #likewise, we can cheat the annoying math needed by using the ipaddress class
                sourceCIDRS.append(network.with_prefixlen) #add to list to be returned
            
            elif addressObj[0].get('type') == 'iprange': #if it's a range
                start = ipaddress.IPv4Address(addressObj[0].get('start-ip')) #create ipv4 address objects - can't do math on them normally but the class allows for casting to int for comparison
                end = ipaddress.IPv4Address(addressObj[0].get('end-ip'))

                for ip in range (int(start), int(end) + 1):
                    ip_current = ipaddress.IPv4Address(ip) #create an address based on where we are in loop
                    network = ipaddress.IPv4Network(f"{ip_current}/32") #make a network so we can add the CIDR below
                    sourceCIDRS.append(network.with_prefixlen) #fake the CIDR since each is a host
                
        return sourceCIDRS