#todo - handle groups, get services

import fortigate_api
from helpers import loadAPI
import ipaddress
import json

class Policy:
    def __init__(self, policyName):
        self.api = loadAPI.createAPI()
        call_results = self.api.cmdb.firewall.policy.get(filter=f'"name=={policyName}"') #make API call for policy by name
        if call_results: #if not empty, assign the needed variables to the first API result
            first = call_results[0] #API likes to return a list, but it's always got one object - pretty much any time we directly use the API in here we're going to want to use the first index
            self.name = first.get('name')
            self.dstaddr = first.get('dstaddr')
            self.srcaddr = first.get('srcaddr')
            self.service = first.get('service')
            self.comments = first.get('comments')
        else:
            raise ValueError ("No policies from API")

    def __str__(self):
        return self.name

    #these are the only methods called from main, rest are helpers
    def getSources(self):
        return self._computeCIDRs("src")
    
    def getDestinations(self):
        return self._computeCIDRs("dst")
    
    #methods to return firewall object names from address objects or address groups
    def _getAddressObj(self, addressName):
        objs = list()
        result = self.api.cmdb.firewall.address.get(name=addressName)
        if result:
            return [result[0].get('name')] #from group always returns a list, so it's better to make this a list of a single object as well for consistency's sake
        else:
            objs.extend(self._getAddressFromGroup(addressName)) #if the API call based on object name is empty then it should be a group, so let's make a call for those instead

        return objs
    
    def _getAddressFromGroup(self, addressName): #recursively handle groups and objects - if it's an object, cool! return it. if it's a group, iterate through members and return them
        objs = list()
        result = self.api.cmdb.firewall.addrgrp.get(name=addressName)
        for member in result[0].get('member'):
            objCall = self.api.cmdb.firewall.address.get(name=member.get('name'))
            if objCall:
                objs.append(objCall[0].get('name'))
            else:
                objs.extend(self._getAddressFromGroup(member.get('name')))
        
        return objs
        
    def _computeCIDRs (self, direction):
        if direction == "src": #populate addressNames based on source or destination in policy
            addressNames = self.srcaddr
        elif direction == "dst":
            addressNames = self.dstaddr
        
        addressNameTable = list() #list that will contain the name of every address object based on src/dst list (resolves groups as well)
        for address in addressNames: #step through policy's addresses and get all of the address objects from it
            if address.get('name') not in ("all", "any"):
                addressNameTable.append(self._getAddressObj(address.get('name')))
        
        flatTable = [name for sublist in addressNameTable for name in sublist] #flatten the list of addressobject names from list of list of str to list of str

        addressCIDRs = list() #create an empty list for CIDRs
        for address in flatTable: #walk through addressobject names, call their data from the firewall, and convert them to a CIDR
            addrCall = self.api.cmdb.firewall.address.get(name=address)
            addrObj = addrCall[0]
            if addrObj.get('type') == 'ipmask': #if it's a subnet or individual host
                addressRaw = addrObj.get('subnet') #pull the ip info from the object
                ip, netmask = addressRaw.split() #it's always one string, formatted [<ip address> <subnetmask>] so instead of regex we can just use split to assign ip and netmask
                network = ipaddress.IPv4Network((ip, netmask),strict=False) #likewise, we can cheat the annoying math needed by using the ipaddress class
                addressCIDRs.append(network.with_prefixlen) #add to list to be returned
            
            elif addrObj.get('type') == 'iprange': #if it's a range
                start = ipaddress.IPv4Address(addrObj.get('start-ip')) #create ipv4 address objects - can't do math on them normally but the class allows for casting to int for comparison
                end = ipaddress.IPv4Address(addrObj.get('end-ip'))

                for ip in range (int(start), int(end) + 1):
                    ip_current = ipaddress.IPv4Address(ip) #create an address based on where we are in loop
                    network = ipaddress.IPv4Network(f"{ip_current}/32") #make a network so we can add the CIDR below
                    addressCIDRs.append(network.with_prefixlen) #fake the CIDR since each is a host

        return addressCIDRs #return the list of CIDRs