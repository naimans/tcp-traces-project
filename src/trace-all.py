#!/usr/bin/env python

import sys
from plt_testing import *
import time
import struct
import json
import ipaddress

#trace as input
t = get_example_trace(sys.argv[1])
portCombination = sys.argv[2]
jsonFile = sys.argv[3]

json_output = {}


fjson = open(jsonFile,) # Opening JSON file
jsonData = json.load(fjson) # returns JSON object as a dictionary

def ipv4function():
    ip_DSCP_ECN = ip.traffic_class
    DSCP = ip_DSCP_ECN >> 2
    ECN = ip_DSCP_ECN & 0x03
    ip_pair = (str(ip.src_prefix), str(ip.dst_prefix), ip.ident)
    
    if ip.version != 4 or ip.hdr_len != 5 or DSCP != 0 or ECN != 0 or (ip.proto != 1 and ip.proto != 6 and ip.proto != 17):
        print("hello")
        json_output[ip_pair] = {"version": ip.version, "identification": ip.ident}

    #for bill in jsonData['$or']:
        #print(bill)
    #or_list = jsonData['or']
    #print(len(or_list))
    #for i in range(len(or_list)):
        #print(or_list[i]['offset'])

    length = jsonData['offset'] + jsonData['length']
    ip_buffer = ip.data[jsonData['offset']:length]
    value = int.from_bytes(ip_buffer, byteorder='big') #byteorder=sys.byteorder
    # print(ipaddress.ip_address(value))
    # print("ip")
    # print(ip.src_prefix)

def tcpfunction(): # For all the tcp connections
    equal = "False"
    
    if ip:
        ip_pair = (str(ip.src_prefix), str(ip.dst_prefix), tcp.src_port, tcp.dst_port)
    if ip6:
        ip_pair = (str(ip6.src_prefix), str(ip6.dst_prefix), tcp.src_port, tcp.dst_port)
    
    or_list = jsonData['or']
    dicts = {}
    
    for i in range(len(or_list)):
        length = or_list[i]['offset'] + or_list[i]['length']
        tcp_buffer = tcp.data[or_list[i]['offset']:length]

        #value = tcp_buffer.decode() #cant use decode
        value = int.from_bytes(tcp_buffer, byteorder='big')
        result = value & or_list[i]['bitmask']
        if result != 0:
            dicts[i] = result
    json_output[ip_pair] = dicts


def udpfunction():
    #print(udp.data)
    ip_pair = (str(ip.src_prefix), str(ip.dst_prefix), udp.src_port, udp.dst_port)
    
    length = jsonData['offset'] + jsonData['length']
    udp_buffer = udp.data[jsonData['offset']:length]
    value = int.from_bytes(udp_buffer, byteorder='big')
    
    if value == 0:
        json_output[ip_pair] = {"checksum": value}

def icmpfunction():
    #print("hello")
    ip_pair = (str(ip.src_prefix), str(ip.dst_prefix), udp.src_port, udp.dst_port)
    json_output[ip_pair] = {"type": icmp.type}

startTime = time.time() #just to calculate the time of the trace parsing

if jsonData['proto'] == 1 or jsonData['proto'] == 4:
    for pkt in t:
        ip = pkt.ip    #to get the ipv4 object
        icmp = pkt.icmp #to get the icmp object

        if ip and icmp:
            icmpfunction()
        
        if ip and not icmp:
            ipv4function()

if (portCombination == "ee"): #even-even port combination
    for pkt in t:
        #if (n%10000 == 0):
            #print("size", sys.getsizeof(connections), len(connections))
        tcp = pkt.tcp  #we get the tcp object
        ip = pkt.ip    #to get the ipv4 object
        ip6 = pkt.ip6 #to get the ipv6 object
        udp = pkt.udp #to get the udp object
        icmp = pkt.icmp #to get the icmp object
        #print(dir(udp))

        if jsonData['proto'] == 6:
            if tcp:
                if (tcp.src_port%2) == 0 and (tcp.dst_port%2) == 0:
                    tcpfunction()

        if jsonData['proto'] == 17:
            if ip and udp:
                if (udp.src_port%2) == 0 and (udp.dst_port%2) == 0:
                    udpfunction()

elif (portCombination == "eo"):
    for pkt in t:
        tcp = pkt.tcp  #we get the tcp object
        ip = pkt.ip    #to get the ipv4 object
        ip6 = pkt.ip6 #to get the ipv6 object
        udp = pkt.udp #to get the udp object
        icmp = pkt.icmp #to get the icmp object
        if jsonData['proto'] == 6:
            if tcp:
                if (tcp.src_port%2) == 0 and (tcp.dst_port%2) == 1:
                    tcpfunction()

        if jsonData['proto'] == 17:
            if ip and udp:
                if (udp.src_port%2) == 0 and (udp.dst_port%2) == 1:
                    udpfunction()

elif (portCombination == "oe"):
    for pkt in t:
        tcp = pkt.tcp  #we get the tcp object
        ip = pkt.ip    #to get the ipv4 object
        ip6 = pkt.ip6 #to get the ipv6 object
        udp = pkt.udp #to get the udp object
        icmp = pkt.icmp #to get the icmp object
        if jsonData['proto'] == 6:
            if tcp:
                if (tcp.src_port%2) == 1 and (tcp.dst_port%2) == 0:
                    tcpfunction()

        if jsonData['proto'] == 17:
            if ip and udp:
                if (udp.src_port%2) == 1 and (udp.dst_port%2) == 0:
                    udpfunction()

elif (portCombination == "oo"):
    for pkt in t:
        tcp = pkt.tcp  #we get the tcp object
        ip = pkt.ip    #to get the ipv4 object
        ip6 = pkt.ip6 #to get the ipv6 object
        udp = pkt.udp #to get the udp object
        icmp = pkt.icmp #to get the icmp object
        if jsonData['proto'] == 6:
            if tcp:
                if (tcp.src_port%2) == 1 and (tcp.dst_port%2) == 1:
                    tcpfunction()

        if jsonData['proto'] == 17:
            if ip and udp:
                if (udp.src_port%2) == 1 and (udp.dst_port%2) == 1:
                    udpfunction()

else:
    print("Not a valid port combination")
    exit()

with open('json_output_proto_'+'_'+str(jsonData['proto']), 'w') as f:
    for key, value in json_output.items():
        f.write (str(key) + " : " + str(value) + "\n" )

print ("Time needed: ", time.time() - startTime)
t.close()  # Don't do this inside the loop!