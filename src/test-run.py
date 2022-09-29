#!/usr/bin/env python

import plt  # Also imports ipp and datetime
import sys
from plt_testing import *
import time
import struct
import json
import ipaddress
import pandas as pd
import csv

#trace as input
t = get_example_trace(sys.argv[1])
jsonFile = sys.argv[2]

ipv4_output = {}
ipv6_output = {}
tcp_output = {}
udp_output = {}
icmp_output = {}
tcp_options = {}
test_dict = {}

fjson = open(jsonFile,) # Opening JSON file
jsonData = json.load(fjson) # returns JSON object as a dictionary

def mainfunction(test_list, test_dict, pckt):
    #print(pckt)
    for i in range(len(test_list)):
        equal = "False"
        val_list = test_list[i]['value']
        #list_check = isinstance(val_list, list)
        length = test_list[i]['offset'] + test_list[i]['length']
        data_buffer = int.from_bytes(pckt.data[test_list[i]['offset']:length], byteorder='big')
        if "rs" in test_list[i]:
            data_buffer = data_buffer >> test_list[i]['rs']
        if "ls" in test_list[i]:
            data_buffer = data_buffer << test_list[i]['ls']
        if "rs2" in test_list[i]:
            data_buffer = data_buffer >> test_list[i]['rs2']
        if "ls2" in test_list[i]:
            data_buffer = data_buffer << test_list[i]['ls2']
        value = data_buffer & test_list[i]['bitmask']
        if isinstance(val_list, list) == True:
            for j in range(len(val_list)):
                if value == val_list[j]:
                    equal = "True"
        else:
            if value == test_list[i]['value']:
                equal = "True"
        if equal == test_list[i]['equal']:
            test_dict.update({test_list[i]['fn'] : value})
    return test_dict

def ipv4function():
    ip_pair = (str(ip.src_prefix), str(ip.dst_prefix), ip.ident)    
    ipv4_list = jsonData['proto']['ipv4']['and']
    #print(len(ipv4_list))
    mainfunction(ipv4_list,test_dict,ip)
    if test_dict:
        #print(test_dict)
        ipv4_output[ip_pair] = dict(test_dict)
        ot.write_packet(pkt)
    test_dict.clear()

def ipv6function():
    ip_pair = (str(ip6.src_prefix), str(ip6.dst_prefix))
    ipv6_list = jsonData['proto']['ipv6']['and']
    test_dict = {}
    mainfunction(ipv6_list,test_dict,ip6)

    if test_dict:
        ipv6_output[ip_pair] = dict(test_dict)
        ot.write_packet(pkt)
    test_dict.clear()

def tcpfunction(): # For all the tcp connections
    ip_pair = (str(tcp.src_prefix), str(tcp.dst_prefix), tcp.src_port, tcp.dst_port)
    tcp_list = jsonData['proto']['tcp']['and']
    
    if tcp.option_numbers:
        tcp_options[ip_pair] = {"options_num": int.from_bytes(tcp.option_numbers, byteorder='big')}

    mainfunction(tcp_list,test_dict,tcp)

    if test_dict:
        #print(test_dict)
        tcp_output[ip_pair] = dict(test_dict)
        ot.write_packet(pkt)
    test_dict.clear()

def udpfunction():
    ip_pair = (str(udp.src_prefix), str(udp.dst_prefix), udp.src_port, udp.dst_port)
    udp_length = ip.pkt_len - ip.hdr_len - 15

    if udp.len != udp_length:
        udp_output[ip_pair] = {"Lenght": udp.len}
        ot.write_packet(pkt)
    
    else:
        if (udp.checksum != 0 or udp.checksum == 0):
            udp_output[ip_pair] = {"checksum": udp.checksum}
            ot.write_packet(pkt)

def icmpfunction():
    ip_pair = (str(icmp.src_prefix), str(icmp.dst_prefix))
    icmp_list = jsonData['proto']['icmp4']['and']
    mainfunction(icmp_list,test_dict,icmp)
    if test_dict:
        icmp_output[ip_pair] = dict(test_dict)
        ot.write_packet(pkt)
    test_dict.clear()

startTime = time.time() #just to calculate the time of the trace parsing
ot = plt.output_trace('pcapfile:sniffed.pcap')
ot.start_output()

for pkt in t:
    ip = pkt.ip    #to get the ipv4 object
    ip6 = pkt.ip6 #to get the ipv6 object
    tcp = pkt.tcp  #to get the tcp object
    udp = pkt.udp #to get the udp object
    icmp = pkt.icmp #to get the icmp object
    #print(dir(pkt))

    if ip:
        ipv4function()
        if udp:
            udpfunction()
    if ip6:
        ipv6function()
    if tcp:
        tcpfunction()    
    if icmp:
        icmpfunction()

#print(type(udp_output))
ipv4 = pd.DataFrame.from_dict({i: ipv4_output[i]
                           for i in ipv4_output.keys()},
                       orient='index')
ipv4.to_csv(r'output_ipv4_'+str(sys.argv[1]).rsplit('.', )[0]+'.csv')

ipv6 = pd.DataFrame.from_dict({i: ipv6_output[i]
                           for i in ipv6_output.keys()},
                       orient='index')
ipv6.to_csv(r'output_ipv6_'+str(sys.argv[1]).rsplit('.', )[0]+'.csv')

tcp = pd.DataFrame.from_dict({i: tcp_output[i]
                           for i in tcp_output.keys()},
                       orient='index')
tcp.to_csv(r'output_tcp_'+str(sys.argv[1]).rsplit('.', )[0]+'.csv')

udp = pd.DataFrame.from_dict({i: udp_output[i]
                           for i in udp_output.keys()},
                       orient='index')
udp.to_csv(r'output_udp_'+str(sys.argv[1]).rsplit('.', )[0]+'.csv')

icmp = pd.DataFrame.from_dict({i: icmp_output[i]
                           for i in icmp_output.keys()},
                       orient='index')
icmp.to_csv(r'output_icmp_'+str(sys.argv[1]).rsplit('.', )[0]+'.csv')

tcpopt = pd.DataFrame.from_dict({i: tcp_options[i]
                           for i in tcp_options.keys()},
                       orient='index')
tcpopt.to_csv(r'output_tcp_options_'+str(sys.argv[1]).rsplit('.',)[0]+'.csv')

print ("Time needed: ", time.time() - startTime)
ot.close_output()
t.close()  # Don't do this inside the loop!