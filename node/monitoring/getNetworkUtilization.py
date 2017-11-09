#!/usr/bin/python
# Sensor zur Bestimmung der Last einer Netzwerkschnittstelle über das ProcFS

import sys
import time
import string

def parse_net_dev (file, interface):
    result = (0, 0)
    f = open (file, "r")
    lines = f.readlines()
    for line in lines:
        if string.find(line, interface) != -1:
            values = [x for x in line.split(" ") if x != ""]
            rx = int(values[0].partition(":")[2])
            tx = int(values[8])
            result = (rx, tx)
    f.close()
    return result

if (len (sys.argv)  >1 and (sys.argv[1] == "-h" or sys.argv[1] == "--help")):
    print ("usage: getNetWorkUtilization.py [<interface>]")
    print ("       default interface is eth0")
    exit (1)

if len(sys.argv) < 2:
    #use eth0 for default
    interface = "eth0"
else:
    interface = sys.argv[1]
try:    
    filename = "/proc/net/dev"
    value1 = parse_net_dev (filename, interface)
    time.sleep(1)
    value2 = parse_net_dev (filename, interface)   
    result = max((value2[0] - value1[0]), (value2[1] - value1[1]))/1024
    print (result)
    exit (0)
except IOError:
    #Cannot read /proc/net/dev
    print ("0")
    exit (1)
    
