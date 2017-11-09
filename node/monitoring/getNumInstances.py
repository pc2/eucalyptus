#!/usr/bin/python
# Sensor zur Bestimmung der Last in Form der Anzahl laufender VMs

import libvirt

conn = libvirt.openReadOnly(None)
try:
    print conn.numOfDomains()-1
except:
    print 0
    exit(1)
exit(0)
