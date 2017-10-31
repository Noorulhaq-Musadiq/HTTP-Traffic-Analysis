import subprocess
import shlex

def doCommand(command):
    command = shlex.split(command)
    packets = subprocess.call(command)

update = 'apt-get update'
tshark = 'apt-get install -u tshark'
httpagentparser = 'pip install httpagentparser'

doCommand(update)
doCommand(tshark)
doCommand(httpagentparser)
