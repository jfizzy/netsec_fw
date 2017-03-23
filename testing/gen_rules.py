import random
import socket
import struct
import sys
import traceback

class Rule:
    """  """
    def __init__(self, direction, action, ip, ports, mask, flag):
        self._direction = direction
        self._action = action
        self._ip = ip
        self._mask = mask
        self._ports = ports
        self._flag = flag
        
    def __str__(self):
        my_str = self._direction + "\t" + self._action + "\t"
        if self._ip == '*':
            my_str += self._ip
        else:
            my_str += self._ip + "/" + str(self._mask)
            
        my_str += "\t" + ",".join(str(p) for p in self._ports)
        
        if self._flag:
            my_str += "\t" + str(self._flag)
            
        return str(my_str)

def generateRules(rules, numRules):
    """ """
    for i in range(0, numRules):

        ipRNG = random.randrange(1,10)

        # 1 in 10 ips will be set to *
        if ipRNG == 1:
            ip = "*"
            mask = None
        else:
            ip = IPHelper.longToIp(random.getrandbits(32))
            mask = random.randrange(8, 33)
            
        numPorts = random.randrange(1, 5)
        ports = []

        # if numPorts is 5, allow any
        if numPorts == 4:
            ports = ['*']
        else:
            for j in range(0, numPorts):
                ports += [random.randrange(1, 65536)]

        directionRNG = random.randrange(0, 2)
        if directionRNG == 0:
            direction = "in"
        else:
            direction = "out"

        actionRNG = random.randrange(0,2)
        if actionRNG == 0:
            action = "accept"
        else:
            action = "deny"

        establishedRNG = random.randrange(0,2)

        if establishedRNG == 0:
            established = "established"
        else:
            established = None

        rule = Rule(direction, action, ip, ports, mask, established)
        rules += [rule]
        
        
class IPHelper:
    @staticmethod
    def ipToLong(ip):
        """ takes in a string format ip and converts it to a long int """
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]

    @staticmethod
    def longToIp(longIp):
        """ takes in a long format ip and converts it to a string """
        stringIp = socket.inet_ntoa(struct.pack("!L", longIp))
        return stringIp



if __name__ == "__main__":
    """ do stuff """

    if len(sys.argv) < 3:
        print("Invalid usage. Use {0} [num_rules] [output_file]".format(sys.argv[0]))
    else:
        try:
            numRules = int(sys.argv[1])
            rules = []
            generateRules(rules, numRules)
            
            with open(sys.argv[2], "w") as fd:
                for rule in rules:
                    fd.write(rule.__str__())
                    fd.write("\n")
                    
        except:
            print("wut, somethin bad happened. " + traceback.format_exc())


