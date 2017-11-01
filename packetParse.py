#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 26 12:44:39 2017

@author: TheKingOfShade
Traffic Analysis Tool
"""
import argparse
import httpagentparser
import subprocess
import shlex
import csv

parser = argparse.ArgumentParser()
parser.add_argument("pcap", type=str, help="Decrypted PCAP that you want to analyze")
parser.add_argument("-d","--nouri", help="Disable URI display for clients", action="store_true")
parser.add_argument("-w","--csv",type=str,help="Write output to CSV",action="store")
args = parser.parse_args()

csvfile = args.csv
PCAP = args.pcap.strip()
NoURI = args.nouri

def getCommand(command):
    command = shlex.split(command)
    ret = []
    packets = subprocess.check_output(command).split('\n')
    for i in packets:
        g = i.split('~')
        if g not in ret:
            ret.append(g)
    ret.remove([''])
    return ret

AP_info_command = 'tshark -r '+ PCAP + ' -2 -R wlan.fc.type_subtype==8 -T fields -E separator="~" -e wlan.sa -e wlan.ssid -e wlan.ds.current_channel -e wlan.extended_supported_rates -e wlan.tag.number -e wlan.rsn.gcs.type'
client_info_command = 'tshark -r ' + PCAP + ' -2 -R http.user_agent -T fields -E separator="~" -e http.user_agent -e ip.src -e ip.dst -e wlan.sa -e wlan.bssid -e http.request.full_uri'
IP_info_command = 'tshark -r '+ PCAP + ' -2 -R arp -T fields -E separator="~" -e arp.src.proto_ipv4 -e arp.src.hw_mac -e wlan.bssid'
	
TSHARK = getCommand(client_info_command)
TSHARK_AP = getCommand(AP_info_command)
TSHARK_IP = getCommand(IP_info_command)

with open('./betterOUI') as b:
    OUI = b.readlines()

class Device():
    'Default Class for Devices On Network'
    def __init__(self, mac):
        self.mac = mac
        self.ip_addr = []
        self.oui = getOUI(mac)
        self.access_point = []

class Client(Device):
    'Default Class for Network Clients'
    def __init__(self,mac):
        Device.__init__(self,mac)
        self.user_agent_string = []
        self.dest_ips = []
        self.uris = []
        self.user_agent_ip = []
        self.os = []
        self.browser = []

class AccessPoint(Device):
    'Default Class For Access Points'
    def __init__(self, mac):
        Device.__init__(self, mac)
        self.SSID = ''
        self.mode = ''
        self.channel = ''
        self.enc = ''

def getOUI(mac):
    mac = str(mac).upper()
    mac = mac.replace(':','')
    mac = mac[:6]
    for line in OUI:
        line = line.split('~')
        if line[0] == mac:
            return line[1].strip()

RETClient = {}
for packet in TSHARK:
    uaString = packet[0]
    ipSource = packet[1]
    ipDestination = packet[2]
    macSource = packet[3]
    macAP = packet[4]
    uri = packet[5]
    uAIP = (ipDestination, uaString)
    if macSource not in RETClient:
        RETClient[macSource] = Client(macSource)
    i = RETClient[macSource]
    i.ip_addr.append(ipSource)
    i.user_agent_string.append(uaString)
    i.access_point.append(macAP)
    i.dest_ips.append(ipDestination)
    i.uris.append(uri)
    i.user_agent_ip.append(uAIP)
    uaParse = httpagentparser.simple_detect(uaString)
    i.os.append(uaParse[0])
    i.browser.append(uaParse[1])

RETAp = {}
for packet in TSHARK_AP:
    bssid = packet[0]
    ssid = packet[1]
    channel = packet[2]
    extended_supported_rates = packet[3].split(',')
    tags = packet[4].split(',')
    if packet[5] == '':
        pass
    else:
        cypher = packet[5]
    if bssid not in RETAp:
        RETAp[bssid]= AccessPoint(bssid)
    i = RETAp[bssid]
    i.ssid = ssid
    i.channel = channel
    if '191' in tags:
        i.mode = 'AC'
    elif '45' in tags:
        i.mode = 'N'
    elif '108' in extended_supported_rates:
        i.mode = 'G'
    elif int(channel) > 14:
        i.mode = 'A'
    else:
        i.mode = 'B'
    if int(cypher) == 4:
        i.enc = 'WPA'
    elif int(cypher) == 2:
        i.enc = 'WPA2'
    else:
        i.enc = 'OPEN or WEP'
    i.access_point = bssid

devices = {}
for packet in TSHARK_IP:
    ip = packet[0]
    mac = packet[1]
    bssid = packet[2]
    devices[mac] = Device(mac)
    devices[mac].ip_addr.append(ip)
    devices[mac].access_point.append(bssid)
    if mac in RETClient:
        RETClient[mac].ip_addr.append(ip)
    elif mac in RETAp:
        RETAp[mac].ip_addr.append(ip)

for k, v in RETClient.items():
    v.user_agent_ip = set(v.user_agent_ip)
    v.ip_addr = set(v.ip_addr)
    v.user_agent_string = set(v.user_agent_string)
    v.access_point = set(v.access_point)
    v.dest_ips = set(v.dest_ips)
    v.uris = set(v.uris)
    
for k, v in RETAp.items():
    devices[k]=v
for k, v in RETClient.items():
    devices[k]=v


def print_attribs_Client(mac):
    '''Print the attributes of a Client'''
    print "<--------------------------------------------------------->"
    p = RETClient[mac]
    print "Client is: " + str(mac) + ' ('+ str(p.oui) + ') '
    print "IP's this client has used: "
    for ipA in p.ip_addr:
        print ipA
    print "Client has connected to AP's with MACs: "
    for ap in p.access_point:
        print ap + ' ('+ str(getOUI(ap)) + ') '
    if NoURI:
	for ua in p.user_agent_string:
            print "User Agent String is: " + str(ua)
            print "Information for that User Agent is: "
            print httpagentparser.simple_detect(ua)
    else:
        for pair in p.user_agent_ip:
            ip_addr = str(pair[0])
            user_agent = str(pair[1])
            print "Client Navigated to " + ip_addr + " using UA String: " + user_agent
            print "Here is the info for that User Agent String:"
            print httpagentparser.simple_detect(user_agent)
            print
	    print
            print "URIs this client has Navigated To:"
            for uri in p.uris:
	        print uri.strip() + '\n'

def print_attribs_AP(mac):
    '''Prints Access Point Attributes'''
    print '###########################################################'
    p = RETAp[mac]
    print "BSSID is: " + str(mac) + ' ('+ str(p.oui) + ') '
    print "IP is : " + str(p.ip_addr)
    print "SSID is: " + p.ssid
    print "Channel Collected was: " + p.channel
    print "Mode seems to be: " + p.mode
    print "Encryption is: " + p.enc

def print_attribs_Device(mac):
    '''Prints Other Device Attributes'''
    if mac not in RETAp:
        if mac not in RETClient:
            p = devices[mac]
            print '*****************************************************'
            print 'Mac is: ' + str(mac) + ' ('+ str(p.oui) + ') '
            for i in p.ip_addr:
                print 'IP is: ' + str(i)
            for j in p.access_point:
                print 'This is associated with BSSID: ' + str(j) + ' ('+ str(getOUI(j)) + ') '

def writeToCSV(dic):
    with open(csvfile,'w') as csvf:
        fieldnames = ['MAC','OUI','BSSID','BSSID-OUI','SSID','CHANNEL','OS','BROWSER']
        writer = csv.DictWriter(csvf,fieldnames=fieldnames)
        writer.writeheader()
        rows = []
        for k, v in dic.items():
            mac = str(v.mac)
            oui = getOUI(mac)
            ip = str(v.ip_addr)
            bssid = str(v.bssid)
            bssid_oui = getOUI(bssid)
            ssid = str(dic[bssid].ssid)
            channel = str(dic[bssid].channel)
            try:
                if len(v.user_agent_strings) > 0:
                    for ua in v.user_agent_strings:
                        uaParse = httpagentparse.simple_detect(ua)
                        os = uaParse[0]
                        browser = uaParse[1]
                        row = {'MAC':mac,'OUI':oui,'BSSID':bssid,'BSSID-OUI':bssid_oui,'SSID':ssid,'CHANNEL':channel,'OS':os,'BROWSER':browser}
                        rows.append(row)
            except:
                row ={'MAC':mac,'OUI':oui,'BSSID':bssid,'BSSID-OUI':bssid_oui,'SSID':ssid,'CHANNEL':channel,'OS':'','BROWSER':''}
                rows.append(row)
        for i in rows:
            writer.writerow(i)

try:
    if len(csvfile) > 0:
        writeToCSV(devices)
except:
    pass

if __name__ == "__main__":
    for k, v in RETAp.items():
        print_attribs_AP(k)
    for k, v in RETClient.items():
        print_attribs_Client(k)
    for k, v in devices.items():
        print_attribs_Device(k)
