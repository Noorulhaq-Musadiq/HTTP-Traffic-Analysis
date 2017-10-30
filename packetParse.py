#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 26 12:44:39 2017

@author: TheKingOfShade
Traffic Analysis Tool
"""
import csv
import httpagentparser

with open('./tsharkOutput') as t:
    TSHARK = t.readlines()

class Device():
    'Default Class for Devices On Network'
    def __init__(self, mac):
        self.mac = mac
        self.ip_addr = []
        self.user_agent_string = []
        self.access_point = []
        self.dest_ips = []
        self.uris = []
        self.user_agent_ip = []



RET = {}
for line in TSHARK:
    packet = line.split("~")
    uaString = packet[0]
    ipSource = packet[1]
    ipDestination = packet[2]
    macSource = packet[3]
    macAP = packet[4]
    uri = packet[5]
    uAIP = (ipDestination, uaString)
    if macSource not in RET:
        RET[macSource] = Device(macSource)
    i = RET[macSource]
    i.ip_addr.append(ipSource)
    i.user_agent_string.append(uaString)
    i.access_point.append(macAP)
    i.dest_ips.append(ipDestination)
    i.uris.append(uri)
    i.user_agent_ip.append(uAIP)

for k, v in RET.items():
    v.user_agent_ip = set(v.user_agent_ip)
    v.ip_addr = set(v.ip_addr)
    v.user_agent_string = set(v.user_agent_string)
    v.access_point = set(v.access_point)
    v.dest_ips = set(v.dest_ips)
    v.uris = set(v.uris)


def print_attribs(mac):
    '''Print the attributes of a device'''
    print "<--------------------------------------------------------->"
    p = RET[mac]
    print "Client is: " + str(mac)
    print "IP's this client has used: "
    for ipA in p.ip_addr:
        print ipA
    print "Client has connected to AP's with MACs: "
    for ap in p.access_point:
        print ap
    for pair in p.user_agent_ip:
        ip_addr = str(pair[0])
        user_agent = str(pair[1])
        print "Client Navigated to " + ip_addr + " using UA String: " + user_agent
        print "Here is the info for that User Agent String:"
        print httpagentparser.detect(user_agent)
    print "URIs this client has Navigated To:"
    for uri in p.uris:
        print uri


if __name__ == "__main__":
    for k, v in RET.items():
        print_attribs(k)
    
