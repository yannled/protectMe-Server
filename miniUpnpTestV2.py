#import os
#import sys

#scriptpath = "portforwardlib.py"
#sys.path.append(os.path.abspath(scriptpath))

import portforwardlib

result = portforwardlib.forwardPort('443','433', "10.0.0.1", None, True, 'TCP', 0, "protectmeVPN", True)
print(result)
