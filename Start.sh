#!/bin/bash
PCAPS=./pcaps/*
for f in $PCAPS
do
	tshark -r $f -2 -R http.user_agent -T fields -E separator="~" -e http.user_agent -e ip.src -e ip.dst -e wlan.sa -e wlan.da -e http.request.full_uri | sort -u > tsharkOutputHTTP
	tshark -r pcaps/20170718-183135028.pcap -2 -R wlan.fc.type_subtype==8 -T fields -E separator="~" -e wlan.sa -e wlan.ssid -e wlan.ds.current_channel -e wlan.extended_supported_rates -e wlan.tag.number -e wlan.rsn.gcs.type | sort -u >tsharkOutputAP
	echo $f >> Output	
	python packetParse.py >> Output
	rm tsharkOutput*
done
cat Output
