#!/bin/bash

echo Choose a port combinatin:
echo ee - even-even
echo eo - even-odd
echo oe - odd-even
echo oo - odd-odd

read -p 'Ans:' var1

sudo python3 track-traces.py teacup.pcap $var1 tcp.json

