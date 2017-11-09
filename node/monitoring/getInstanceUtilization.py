#!/usr/bin/python
# Sensor zur Bestimmung der Last virtueller Prozessoren einer VM

import libvirt
import sys
import time

if len(sys.argv)<2:
    print ("0")
    exit (1);

instanceId = sys.argv[1]
conn = libvirt.openReadOnly(None)
util1 = []
util2 = []
result = 0
domain = conn.lookupByName (instanceId)
vcpus = domain.vcpus()
for vcpu in vcpus[0]:
    util1.append (vcpu[2])
time.sleep(0.1)
vcpus = domain.vcpus()
for vcpu in vcpus[0]:
    util2.append (vcpu[2])
for i in range (len(util1)):
    result += (util2[i] - util1[i]) / (1000*1000) #to get result between 0 and 100
print (result)
exit (0)	
