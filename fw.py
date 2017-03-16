import socket
import struct
import sys
import traceback

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class RuleManager:
    def __init__(self):
        """ """
        self._rules = []

    def parseRules(self, filename):
        """ parses multiple rules. Given a filename, it will parse the rules one line at a time checking for format """

        try:
            with open(filename) as fd:
                #do stuff

                line = fd.readline()
                rule = self.parseRule(line)
                
                while line != '':
                    if rule != None:
                        self._rules.append(rule)

                    line = fd.readline()
                    rule = self.parseRule(line)


            for rule in self._rules:
                eprint(rule)
                
        except:
            # error opening file
            eprint("Error in parseRules: traceback info: {0}".format(traceback.format_exc()))


    def parseRule(self, ruleTxt):
        """ parses a single rule. Expects 1 line of text """
        ruleParts = ruleTxt.split()

        #less than 4 or more than 5 fields, poorly formed rule
        if len(ruleParts) < 4 or len(ruleParts) > 5:
            return None

        direction = ruleParts[0]
        action = ruleParts[1]
        ip = ruleParts[2]
        ports = ruleParts[3]
        flag = ruleParts[4] if len(ruleParts) == 5 else None

        try:
            rule = Rule(direction, action, ip, ports, flag)
        except:
            rule = None
        
        return rule

    def parsePacket(self, packet):
        """ 
        checks to see if a packet conforms to any rules and returns the rule number.
        returns -1 if no rule found
        """
        
        pcktParts = packet.split()
        
        # needs exactly 4 parts
        if len(pcktParts) != 4:
            return None
        
        direction = pcktParts[0]
        ip = pcktParts[1]
        port = pcktParts[2]
        flag = pcktParts[3]

        try:
            pckt = Packet(direction, ip, port, flag)
        except:
            eprint(traceback.format_exc())
            return None
        
        return pckt

    def routePacket(self, packet, rules):
        """
        decides on the route that the current rules dictate for the packet
        """
        rule_counter = 1
        for rule in rules:
            # check rule mask vs packet ip
            ip = IPHelper.ipToLong(packet._ip)
            if rule._raw_ip == '*' or (rule._ip_mask_val & ip == rule._ip_mask_val):
                if rule._direction == packet._direction:
                    for p in rule._ports:
                        if p == packet._port or p == '*':
                            if rule._flag is None:
                                #packet is non-established connection
                                if rule._action == 'accept':
                                    return (True, rule_counter, rule)
                                elif rule._action == 'deny':
                                    return (False, rule_counter, rule)
                            #may not need to return rules
                            elif rule._flag == 'established' and packet._flag == '1':
                                #packet is established connection
                                if rule._action == 'accept':
                                    return (True, rule_counter, rule)
                                elif rule._action == 'deny':
                                    return (False, rule_counter, rule)
                            else:
                                pass
                        else:
                            pass
                else:
                    pass
            else:
                pass

            rule_counter += 1
        return (False, 0, None)
        

class Rule:
    """  """
    def __init__(self, direction, action, ip, ports, flag):
        self._direction = direction

        if self._direction != 'in' and self._direction != 'out':
            raise RuleException("Rule object field 'direction' must be either 'in' or 'out'")
        
        self._action = action

        if self._action != 'accept' and self._action != 'deny' and self._action != 'drop':
            raise RuleException("Rule object field 'action' must be either 'accept', 'deny', or 'drop'")

        self._raw_ip = ip
        
        ip_parts = ip.split("/")
        if len(ip_parts) == 1:
            self._ip_mask_str = ip_parts[0]

            #accept any
            if self._ip_mask_str == '*':
                self._ip_mask_val = 0xFFFFFFFF

        elif len(ip_parts) == 2:
            subnet_mask = ip_parts[1]
            real_ip = ip_parts[0]
            try:
                subnet_mask_raw = int(subnet_mask)
                ipLong = IPHelper.ipToLong(real_ip)

                subnet_mask = 1 << (subnet_mask_raw - 1)
                subnet_mask = subnet_mask | (subnet_mask - 1)
                subnet_mask = subnet_mask << (32 - subnet_mask_raw)

                self._ip_mask_val = subnet_mask & ipLong
                self._ip_mask_str = IPHelper.longToIp(self._ip_mask_val)
            except ValueError:
                #poorly formed subnet mask
                raise RuleException("Malformed subnet mask")
            except:
                #poorly formed ip
                raise RuleException("Malformed ip address")

        else:
            raise RuleException("Malformed ip adress. Contained multiple subnet masks.")
        
        self._ports = ports.split(",")
        self._flag = flag
        
    def __str__(self):
        my_str = "direction: " + self._direction + "\n"
        my_str += "action: " + self._action + "\n"
        my_str += "rule ip: " + self._raw_ip + "\n"
        my_str += "ip mask: " + self._ip_mask_str + "\n"
        my_str += "ip mask binary: {0:b}\n".format(self._ip_mask_val)
        my_str += "ports: " + str(self._ports) + "\n"
        my_str += "flag: " + self._flag + "\n" if self._flag else ""

        return str(my_str)


class RuleException(Exception):
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return repr(self._message)
    

class Packet:
    """  """
    def __init__(self, direction, ip, port, flag):
        self._direction = direction
        if self._direction != 'in' and self._direction != 'out':
            raise PacketException("Packet object field 'direction' must be either 'in' or 'out'")

        try:
            ipLong = IPHelper.ipToLong(ip)
        except:
            raise PacketException("Packet object field 'ip' must be a valid IPv4 address")
        self._ip = ip
            
        if int(port) >=0 and int(port) < 65536:
            self._port = port
        else:
            raise PacketException("Packet object field 'port' must be between 0 and 65535")

        if not (flag == '1' or flag == '0'):
            raise PacketException("Packet object field 'flag' must be either '0' or '1'")
        self._flag = flag
        
    def __str__(self):
        my_str = self._direction + " " + self._ip + " " + \
                 str(self._port) + " " + self._flag
        return str(my_str)

class PacketException(Exception):
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return repr(self._message)

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
    
def main(args = None):
    if len(sys.argv) < 2:
        eprint("Invalid usage. Usage: ")
        eprint("python3 fw.py [rule_filename] < [packets_filename]");
        return

    rules = sys.argv[1]
    rule_manager = RuleManager()
    rule_manager.parseRules(rules)

    if sys.stdin.isatty():
        eprint("No input file received.")
        return
    
    line = sys.stdin.readline()
    while line != '':
        pckt = rule_manager.parsePacket(line)
        if pckt is not None:
            (status, rno, rule) = rule_manager.routePacket(pckt, rule_manager._rules)
            if rno == 0:
                print("drop() {0}".format(pckt.__str__()))
            else:
                print("{0}({1}) {2}".format(rule._action, rno, pckt.__str__()))
        else:
            eprint("Corrupt Packet")
        line = sys.stdin.readline()
    
if __name__ == "__main__":
    main()
    eprint("Exitting...")
