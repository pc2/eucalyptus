#!/usr/bin/python
# Sensor zur Bestimmung von Last in Form der Anzahl genutzter Prozessorkerne

import libvirt
conn = libvirt.openReadOnly(None)
try:
    hwinfo = conn.getInfo()
    domainIds = conn.listDomainsID()
    vcpus = 0
    for id in domainIds:
        domain = conn.lookupByID(id)
        vcpus += domain.maxVcpus()   
    print vcpus-hwinfo[2]
except:
    print 0
    exit(1)
exit(0)
