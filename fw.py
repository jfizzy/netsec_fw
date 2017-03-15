


class Rule:
    """  """
    def __init__(self, direction, action, ip, port, flag):
        self._direction = direction

        if self._direction != 'in' && self._direction != 'out':
            raise RuleException("Rule object field 'direction' must be either 'in' or 'out'")
        
        self._action = action

        if self._action != 'accept' && self._action != 'deny' && self._action != 'drop':
            raise RuleException("Rule object field 'action' must be either 'accept', 'deny', or 'drop'")
        
        self._ip = ip
        self._port = port
        self._flag = flag


class RuleException(Exception):
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return repr(self._message):
