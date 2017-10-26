#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 26 12:44:39 2017

@author: root
Traffic Analysis Tool
"""
with open('./tsharkOutput') as t:
    tshark = t.readlines()

class Device():
    def __init__(self,mac):
        self.mac = mac
        self.ip = []
        self.userAgentString = []
        self.AP = []
        self.destIPs = []
        self.URIs = []
        self.userAgentIP = []

ret = {}
for line in tshark:
    packet = line.split(";")
    uaString = packet[0]
    ipSource = packet[1]
    ipDestination = packet[2]
    macSource =packet[3]
    macAP=packet[4]
    uri=packet[5]
    uAIP = (ipDestination,uaString)
    if macSource not in ret:
        ret[macSource] = Device(macSource)
    i = ret[macSource]
    i.ip.append(ipSource)
    i.userAgentString.append(uaString)
    i.AP.append(macAP)
    i.destIPs.append(ipDestination)
    i.URIs.append(uri)
    i.userAgentIP.append(uAIP)
for k,v in ret.items():
    v.userAgentIP = set(v.userAgentIP)
    v.ip = set(v.ip)
    v.userAgenString = set(v.userAgentString)
    v.AP = set(v.AP)
    v.destIPs = set(v.destIPs)
    v.URIs = set(v.URIs)

def printAttribs(macAddress):
    print("<--------------------------------------------------------->")
    i = ret[macAddress]
    print("Client is: " + str(macAddress))
    print("IP's this client has used: " )
    for j in i.ip:
        print(j)
    print("Client has connected to AP's with MACs: ")
    for j in i.AP:
        print(j)
    for j in i.userAgentIP:
        print("Client Navigated to " + str(j[0]) + " using UA String: " + str(j[1]))
    print("URIs this client has Navigated To:")
    for j in i.URIs:
        print(j)

for k,v in ret.items():
    printAttribs(k)


    
