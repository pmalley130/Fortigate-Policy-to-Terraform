import ipaddress
import fortigate_api
from helpers import loadAPI


#policy object from the firewall with methods to return the sources, destinations, and service from the API
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
            raise ValueError (f"No policy {policyName} from API")

    def __str__(self):
        return f"{self.name}"

    #these are the only methods called from main, rest are helpers
    def getSources(self): #returns list of CIDRs from source objects in policy
        return self._computeCIDRs("src")
    
    def getDestinations(self): #returns list of CIDRs from destination objects in policyy
        return self._computeCIDRs("dst")
    
    def getServices(self): #returns list of services (ports) used in the policy - see Service class for properties
        serviceList = []
        for service in self.service:
            newService = Service(service.get('name'))
            serviceList.append(newService)
        return serviceList
    
    #methods to return firewall object names from address objects or address groups
    def _getAddressObj(self, addressName):
        objs = list()
        result = self.api.cmdb.firewall.address.get(name=addressName)
        if result:
            return [result[0].get('name')] #from group always returns a list, so it's better to make this a list of a single object as well for consistency's sake
        else:
            objs.extend(self._getAddressFromGroup(addressName)) #if the API call based on object name is empty then it should be a group, so let's make a call for those instead

        return objs
    
    def _getAddressFromGroup(self, addressName): #recursively handle groups and objects - if it's an object, cool! return it. if it's a group, iterate through members and return their names
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

        addressCIDRs = self._cleanCIDRs(addressCIDRs) #check to see if any CIDRs are eclipsed, only return bigger ones
        return addressCIDRs #return the list of CIDRs
    
    def _cleanCIDRs(self, CIDRlist): #check list of CIDRs to see if any are eclipsed, remove eclipsed one
        networks = [ipaddress.ip_network(cidr) for cidr in CIDRlist] #create a list of network objects
        result = []

        for network in networks: #step through each network and see if it is contained in other networks, if not, add to results
            if not any(other != network and other.supernet_of(network) for other in networks):
                result.append(str(network))
        
        return result
        
class Service: 
    def __init__(self, serviceName):
        self.api = loadAPI.createAPI()
        call_results = self.api.cmdb.firewall_service.custom.get(name=serviceName) #make API call for service by name
        if call_results: #if not empty, assign the needed variables to the first API result
            first = call_results[0]
            
            #set values for service
            self.name = first.get('name')
            
            if (first.get('tcp-portrange')): #if it has values in tcp-portrange then it's a tcp rule
                self.ip_protocol = "tcp"
            elif(first.get('udp-portrange')):#same for udp
                self.ip_protocol = "udp"
        
            #if there's a "-" in it it's a port range, otherwise just set from_port and to_port to the same(keeping terraform AWS convention)           
            ports = first.get(f"{self.ip_protocol}-portrange")
            if "-" in ports:
                from_port, to_port = map(int, ports.split('-'))
                self.from_port = from_port
                self.to_port = to_port
            else:
                from_port = int(ports)
                self.from_port = from_port
                self.to_port = from_port
            
        else:
            raise ValueError (f"No service {serviceName} from API")
        
    def __str__(self):
        return f"{self.name}"