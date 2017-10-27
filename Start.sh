#!/bin/bash
PCAPS=./pcaps/*
for f in $PCAPS
do
	tshark -r $f -2 -R http.user_agent -T fields -E separator="~" -e http.user_agent -e ip.src -e ip.dst -e wlan.sa -e wlan.da -e http.request.full_uri > tsharkOutput
	python packetParse.py >> Output
	rm tsharkOutput
done
cat Output
