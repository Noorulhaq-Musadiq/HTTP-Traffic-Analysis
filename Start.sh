#!/bin/bash
PCAPS=./pcaps/*
for f in $PCAPS
do
	tshark -r $f -2 -R http.user_agent -T fields -E separator="~" -e http.user_agent -e ip.src -e ip.dst -e wlan.sa -e wlan.da -e http.request.full_uri | sort -u > tsharkOutputHTTP
	tshark -r $f -2 -R wlan.fc.type_subtype==8 -T fields -E separator="~" -e wlan.sa -e wlan_mgt.ssid -e wlan_mgt.ds.current_channel -e wlan_mgt.extended_supported_rates -e wlan_mgt.tag.number -e wlan_mgt.rsn.pcs.type | sort -u >tsharkOutputAP
	python packetParse.py >> Output
	#rm tsharkOutput*
done
cat Output
