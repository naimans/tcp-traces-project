#!/usr/bin/env python

import sys
from plt_testing import *
import time
import struct
import json

#trace as input
t = get_example_trace(sys.argv[1])

#outfiles
#outputFile = sys.argv[2]
#connectionFile = sys.argv[3]
portCombination = sys.argv[2]
#print(portCombination)
#testing

#  '175.240.8.166'       , '30.226.124.87'
#'161.89.80.91', '205.221.42.4'


src = '161.89.80.91'
dst = '205.221.42.4'


verbose = False


#connections info to hold all the data
#infos are  key ((ip tuples and occurences)), values(retransmission, dupack, flowsizes, ackfromrecv, finackfromrecv, synackfromrecv) 
#key: ip pairs, port pairs and occurennce   
#values: C_S_countR/D, retransmission, dupack, flowsizes, syn, fin, synack, lastsentseq, lastackseq (s-c)
#values: S_C_countR/D, S_C_retransmission, S_C_dupack, flowsizes, lastsentseq, lastackseq (c-s)
connections = {}
connections_ip6 = {}
connections_occurences = {}
#not to exhaust the memory with storing unnecessary connections with only syn but not synack or fin      


connections_syn= {}  # key(tuple): values[syn, pkt_len]
json_output = {}

#to access keys

count_c2s = 0
retx_c2s = 1
dupack_s2c = 2
fsize_c2s = 3
syn = 4
finack  = 5
synack = 6
lastsentseq_c2s = 7
lastackseq_s2c = 8

count_s2c = 9
retx_s2c = 10
dupack_c2s = 11
fsize_s2c = 12
lastsentseq_s2c = 13
lastackseq_c2s = 14

seq_dict_c2s = 15
ack_dict_s2c = 16

seq_dict_s2c = 17
ack_dict_c2s = 18


count = 0
n = 0
countrtx = 0
countdup = 0
countcc = 0


#connectionFile = "conn_occ"
#outputFile = "conn_ip4"
#outputFile_1 = "conn_ip6"

fjson = open('json_data.json',) # Opening JSON file
jsonData = json.load(fjson) # returns JSON object as a dictionary

#key_list = list(jsonData.keys())

def myfunction():
    global count_c2s, count_s2c, retx_c2s, retx_s2c, dupack_c2s, dupack_s2c, fsize_c2s, fsize_s2c, syn, finack, synack, lastackseq_c2s, lastsentseq_s2c, lastsentseq_c2s, lastackseq_s2c
    global seq_dict_c2s, seq_dict_s2c, ack_dict_c2s, ack_dict_s2c, count, countrtx, countdup, countcc
    #global key_list
    equal = "False"
    
    if ip:
        hdr_len = ip.hdr_len
        pkt_len = ip.pkt_len
        src_prefix = str(ip.src_prefix)
        dst_prefix = str(ip.dst_prefix)

    if ip6:
        hdr_len=40
        pkt_len = ip6.payload_len+hdr_len
        src_prefix = str(ip6.src_prefix)
        dst_prefix = str(ip6.dst_prefix)

    if  tcp.syn_flag or tcp.fin_flag or tcp.rst_flag:

        #syn packet: we register only connections at this point and set the syn flag for the flow's information
        if tcp.syn_flag and not tcp.ack_flag:  
            #print ("syn packet: first connection registering")

            ip_pair = (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port)

            if tcp:
                if ip:
                    startLen = (hdr_len * 4) + jsonData['offset']
                    length = startLen + jsonData['length']

                if ip6:
                    startLen = hdr_len + jsonData['offset']
                    length = startLen + jsonData['length']

                ip_buffer = tcp.data[startLen:length]
                value = int.from_bytes(ip_buffer, byteorder=sys.byteorder)
                #print(value)
                result = value & jsonData['bitmask']
                #print(result)

                if result == jsonData['value']:
                    equal = "True"

                if equal == jsonData['equal']:
                    json_output[ip_pair] = result

            if ip:
                length = jsonData['offset'] + jsonData['length']
                ip_buffer = ip.data[jsonData['offset']:length]
                value = int.from_bytes(ip_buffer, byteorder=sys.byteorder)
                #print(ip_buffer)
                result = value & jsonData['bitmask']
                #print(result)

                if result == jsonData['value']:
                    equal = "True"

                if equal == jsonData['equal']:
                    json_output[ip_pair] = result

            if ip6:
                length = jsonData['offset'] + jsonData['length']
                ip_buffer = ip6.data[jsonData['offset']:length]
                value = int.from_bytes(ip_buffer, byteorder=sys.byteorder)
                result = value & jsonData['bitmask']

                if result == jsonData['value']:
                    equal = "True"

                if equal == jsonData['equal']:
                    json_output[ip_pair] = result
                    
            if  ip_pair in connections_occurences:
                connections_occurences[ip_pair] += 1
            else:
                connections_occurences[ip_pair] = 1

            connection_key = (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port, connections_occurences[ip_pair])
            #countR/D (0), retransmission (1), dupack (2), flowsizes (3), syn (4), fin (5), synack (6), lastsentseq (7), lastackseq (8)
            #S_C_countR/D (9), S_C_retransmission (10), S_C_dupack (11), flowsizes (12) , lastsentseq (13), lastackseq (c-s) (14)
  
            #connections[connection_key] = [0, 0, 0, ip.pkt_len, 1, 0, 0, 0 ,0, 0, 0, 0 , 0, 0 ,0]

            connections_syn[connection_key] = [1, pkt_len]

            #connections[connection_key] = [0, 0, 0, ip.pkt_len, 1, 0, 0, 0 ,0, 0, 0, 0 , 0, 0 ,0, {}, {}, {} ,{}]    

            if verbose:
                if src_prefix == src and dst_prefix == dst:
                    print (get_tag("n:"+str(n)), ' syn, first packet: match ip', src_prefix, dst_prefix, connection_key, connections_syn[connection_key])

        #synack

        if tcp.syn_flag and tcp.ack_flag:
            ip_pair = (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port)
            if  ip_pair in connections_occurences:
                connection_key = (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port, connections_occurences[ip_pair])
             #   print (connection_key)
                if connection_key in connections_syn: #connections:
                    #print("syn-ack Found")
                    if ip:
                        connections[connection_key] = [0, 0, 0, connections_syn[connection_key][1], connections_syn[connection_key][0], 0, 1, 0 ,0, 0, 0, 0 , pkt_len, 0 ,0, {}, {}, {} ,{}]   
                    if ip6:
                        connections_ip6[connection_key] = [0, 0, 0, connections_syn[connection_key][1], connections_syn[connection_key][0], 0, 1, 0 ,0, 0, 0, 0 , pkt_len, 0 ,0, {}, {}, {} ,{}]

                if verbose:
                    if dst_prefix == src and src_prefix == dst:
                        print (get_tag("n:"+str(n)), ' match ip - syn ack flag: ', src_prefix, dst_prefix, connection_key, connections[connection_key])

        if tcp.fin_flag or tcp.rst_flag:
            #finack from the sender
            if (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port) in connections_occurences: 
                ip_pair = (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port)
                connection_key = (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port, connections_occurences[ip_pair])

                if ip:
                    if connection_key in connections:
                        #print("sender: FIN Found")
                        if tcp.fin_flag:
                            connections[connection_key][finack] = 1
                            connections[connection_key][fsize_c2s] += pkt_len
                            countcc += 1
                            fopen.write(str(connection_key) + " : " + str(connections[connection_key])+ "\n" )
                            connections.pop(connection_key)

                        if verbose:
                            if src_prefix == src and dst_prefix == dst:
                                 print (get_tag("n:"+str(n)), 'finack c2s', src_prefix, dst_prefix, connections[connection_key])
                if ip6:
                    if connection_key in connections_ip6:
                        #print("sender: FIN Found")
                        if tcp.fin_flag:
                            connections_ip6[connection_key][finack] = 1
                            connections_ip6[connection_key][fsize_c2s] += pkt_len
                            countcc += 1
                            fopen6.write(str(connection_key) + " : " + str(connections_ip6[connection_key])+ "\n" )
                            connections_ip6.pop(connection_key)

                        if verbose:
                            if src_prefix == src and dst_prefix == dst:
                                 print (get_tag("n:"+str(n)), 'finack c2s', src_prefix, dst_prefix, connections_ip6[connection_key])

            #finack from the receiver side                
            if (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port) in connections_occurences: 
                ip_pair = (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port)
                connection_key = (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port, connections_occurences[ip_pair])

                if ip:
                    if connection_key in connections:
                        #print("sender: FIN Found")
                        if tcp.fin_flag:
                            connections[connection_key][finack] = 1
                            connections[connection_key][fsize_s2c] += pkt_len
                            countcc += 1
                            fopen.write(str(connection_key) + " : " + str(connections[connection_key])+ "\n" )
                            connections.pop(connection_key)

                        if verbose:
                            if dst_prefix == src and src_prefix == dst:
                                 print (get_tag("n:"+str(n)), 'finack s2c', dst_prefix, "->", src_prefix, connections[connection_key])

                if ip6:
                    if connection_key in connections_ip6:
                        #print("sender: FIN Found")
                        if tcp.fin_flag:
                            connections[connection_key][finack] = 1
                            connections[connection_key][fsize_s2c] += pkt_len
                            countcc += 1
                            fopen.write(str(connection_key) + " : " + str(connections[connection_key])+ "\n" )
                            connections.pop(connection_key)

                        if verbose:
                            if dst_prefix == src and src_prefix == dst:
                                 print (get_tag("n:"+str(n)), 'finack s2c', dst_prefix, "->", src_prefix, connections_ip6[connection_key])                  
    else:
        if ip:
            #sender side packets
            if (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port) in connections_occurences: 
                
                ip_pair = (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port)
                connection_key = (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port, connections_occurences[ip_pair])
                
                if connection_key in connections and (connections[connection_key][syn] == 1 and connections[connection_key][synack] == 1) :
                    if pkt_len - tcp.doff*4 - hdr_len*4 > 0 :     
                        if tcp.seq_nbr <= connections[connection_key][lastsentseq_c2s]:
                            connections[connection_key][fsize_c2s] += pkt_len
                            if tcp.seq_nbr in connections[connection_key][seq_dict_c2s]:
                                if pkt_len == connections[connection_key][seq_dict_c2s][tcp.seq_nbr]:
                                    connections[connection_key][count_c2s] = 1
                                    connections[connection_key][retx_c2s] = 1
                                    countrtx += 1
                                    if verbose:
                                        if src_prefix == src and dst_prefix == dst:
                                            print (get_tag("n:"+str(n)), 'match ip: retx', n, src_prefix, dst_prefix, connection_key, \
                                                connections[connection_key], pkt_len - tcp.doff*4 - hdr_len*4, pkt_len)
                            else:
                                connections[connection_key][seq_dict_c2s][tcp.seq_nbr] = pkt_len
                                count += 1
                                if verbose:
                                    if src_prefix == src and dst_prefix == dst:
                                        print (get_tag("n:"+str(n)), 'match ip: out of order packets', src_prefix, dst_prefix, connection_key, \
                                            connections[connection_key], pkt_len - tcp.doff*4 - hdr_len*4, pkt_len)


                        else:
                            connections[connection_key][seq_dict_c2s][tcp.seq_nbr] = pkt_len
                            #seq_lst[tcp.seq_nbr] = ip.pkt_len
                            connections[connection_key][fsize_c2s] += pkt_len
                            connections[connection_key][lastsentseq_c2s] = tcp.seq_nbr
                            if verbose:
                                if src_prefix == src and dst_prefix == dst:
                                    print (get_tag("n:"+str(n)), 'match ip: not retx', src_prefix, dst_prefix, connection_key, connections[connection_key])
                    else:
                        if tcp.ack_nbr <= connections[connection_key][lastackseq_c2s]:

                            if tcp.ack_nbr in connections[connection_key][ack_dict_c2s]:
                                connections[connection_key][ack_dict_c2s][tcp.ack_nbr] += 1
                                if connections[connection_key][ack_dict_c2s][tcp.ack_nbr] > 3:
                                    #print("3rd dupack ", tcp.ack_nbr, ack_lst[tcp.ack_nbr] )
                                    connections[connection_key][count_s2c] = 1
                                    connections[connection_key][dupack_c2s] = 1
                            else:
                                connections[connection_key][ack_dict_c2s][tcp.ack_nbr] = 1
                            
                            connections[connection_key][fsize_c2s] += pkt_len

                            if verbose:
                                if dst_prefix == dst and src_prefix == src:
                                    print (get_tag("n:"+str(n)), 'dupack part c2s: match ip', connection_key, src_prefix, dst_prefix, connection_key, connections[connection_key],  connections[connection_key][ack_dict_c2s][tcp.ack_nbr], pkt_len - tcp.doff*4 - hdr_len*4, pkt_len)
                        else:
                            #this is an increasing ack
                            connections[connection_key][ack_dict_c2s][tcp.ack_nbr] = 0
                            connections[connection_key][lastackseq_c2s] = tcp.ack_nbr
                            connections[connection_key][fsize_c2s] += pkt_len
                            if verbose:
                                if src_prefix == src and dst_prefix == dst:
                                    print (get_tag("n:"+str(n)), 'regular ack c->s: match ip', src_prefix, dst_prefix, connection_key, connections[connection_key], pkt_len)    
        
            #reciver side packets
            if (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port) in connections_occurences: 
                ip_pair = (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port)
                connection_key = (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port, connections_occurences[ip_pair])
                
                if connection_key in connections and (connections[connection_key][syn] == 1 and connections[connection_key][synack] == 1):

                    if pkt_len - tcp.doff*4 - hdr_len*4 > 0:
                        if tcp.seq_nbr <= connections[connection_key][lastsentseq_s2c]:
                            connections[connection_key][fsize_s2c] += pkt_len #increasing packet length
                            if tcp.seq_nbr in connections[connection_key][seq_dict_s2c]:
                                if pkt_len == connections[connection_key][seq_dict_s2c][tcp.seq_nbr]:
                                    connections[connection_key][count_s2c] = 1
                                    connections[connection_key][retx_s2c] = 1
                                    if verbose:
                                        if src_prefix == dst and sdst_prefix == src:
                                            print (get_tag("n:"+str(n)), 'match ip: retx s->c', n, src_prefix, dst_prefix, connection_key, \
                                                connections[connection_key], pkt_len - tcp.doff*4 - hdr_len*4, pkt_len)
                            else:
                                connections[connection_key][seq_dict_s2c][tcp.seq_nbr] = pkt_len

                        else:
                            connections[connection_key][fsize_s2c] += pkt_len
                            connections[connection_key][seq_dict_s2c][tcp.seq_nbr] = pkt_len
                            connections[connection_key][lastsentseq_c2s] = tcp.seq_nbr
                            if verbose:
                                if src_prefix == dst and dst_prefix == src:
                                    print (get_tag("n:"+str(n)), 'match ip: not retx s->c', src_prefix, dst_prefix, connection_key, connections[connection_key])

                    else:

                        if tcp.ack_nbr <= connections[connection_key][lastackseq_s2c]:

                            countdup += 1

                            if tcp.ack_nbr in connections[connection_key][ack_dict_s2c]:
                                connections[connection_key][ack_dict_s2c][tcp.ack_nbr] += 1
                                if connections[connection_key][ack_dict_s2c][tcp.ack_nbr] > 3:
                                    #print("3rd dupack ", tcp.ack_nbr, ack_lst[tcp.ack_nbr] )
                                    connections[connection_key][count_c2s] = 1
                                    connections[connection_key][dupack_s2c] = 1
                            else:
                                connections[connection_key][ack_dict_s2c][tcp.ack_nbr] = 1

                            connections[connection_key][fsize_s2c] += pkt_len 

                            if verbose:
                                if dst_prefix == src and src_prefix == dst:
                                    print (get_tag("n:"+str(n)), 'dupack part: match ip', connection_key, ssrc_prefix, dst_prefix, connection_key, connections[connection_key],  connections[connection_key][ack_dict_s2c][tcp.ack_nbr])    

                        else:
                            connections[connection_key][ack_dict_s2c][tcp.ack_nbr] = 0
                            connections[connection_key][lastackseq_s2c] = tcp.ack_nbr
                            connections[connection_key][fsize_s2c] += pkt_len 

                            if verbose:
                                if dst_prefix == src and src_prefix == dst:
                                    print (get_tag("n:"+str(n)), 'regular ack: match ip s->c', src_prefix, dst_prefix, connection_key, connections[connection_key],pkt_len)
        
        if ip6:
            #sender side packets
            if (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port) in connections_occurences: 
                
                ip_pair = (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port)
                connection_key = (src_prefix, dst_prefix, tcp.src_port, tcp.dst_port, connections_occurences[ip_pair])
                
                if connection_key in connections_ip6 and (connections_ip6[connection_key][syn] == 1 and connections_ip6[connection_key][synack] == 1) :
                    if pkt_len - tcp.doff*4 - hdr_len*4 > 0 :     
                        if tcp.seq_nbr <= connections_ip6[connection_key][lastsentseq_c2s]:
                            connections_ip6[connection_key][fsize_c2s] += pkt_len
                            if tcp.seq_nbr in connections_ip6[connection_key][seq_dict_c2s]:
                                if pkt_len == connections_ip6[connection_key][seq_dict_c2s][tcp.seq_nbr]:
                                    connections_ip6[connection_key][count_c2s] = 1
                                    connections_ip6[connection_key][retx_c2s] = 1
                                    countrtx += 1
                                    if verbose:
                                        if src_prefix == src and dst_prefix == dst:
                                            print (get_tag("n:"+str(n)), 'match ip: retx', n, src_prefix, dst_prefix, connection_key, \
                                                connections_ip6[connection_key], pkt_len - tcp.doff*4 - hdr_len*4, pkt_len)
                            else:
                                connections_ip6[connection_key][seq_dict_c2s][tcp.seq_nbr] = pkt_len
                                count += 1
                                if verbose:
                                    if src_prefix == src and dst_prefix == dst:
                                        print (get_tag("n:"+str(n)), 'match ip: out of order packets', src_prefix, dst_prefix, connection_key, \
                                            connections_ip6[connection_key], pkt_len - tcp.doff*4 - hdr_len*4, pkt_len)

                        else:
                            connections_ip6[connection_key][seq_dict_c2s][tcp.seq_nbr] = pkt_len
                            #seq_lst[tcp.seq_nbr] = ip.pkt_len
                            connections_ip6[connection_key][fsize_c2s] += pkt_len
                            connections_ip6[connection_key][lastsentseq_c2s] = tcp.seq_nbr
                            if verbose:
                                if src_prefix == src and dst_prefix == dst:
                                    print (get_tag("n:"+str(n)), 'match ip: not retx', src_prefix, dst_prefix, connection_key, connections_ip6[connection_key])
                    else:
                        if tcp.ack_nbr <= connections_ip6[connection_key][lastackseq_c2s]:

                            if tcp.ack_nbr in connections_ip6[connection_key][ack_dict_c2s]:
                                connections_ip6[connection_key][ack_dict_c2s][tcp.ack_nbr] += 1
                                if connections_ip6[connection_key][ack_dict_c2s][tcp.ack_nbr] > 3:
                                    #print("3rd dupack ", tcp.ack_nbr, ack_lst[tcp.ack_nbr] )
                                    connections_ip6[connection_key][count_s2c] = 1
                                    connections_ip6[connection_key][dupack_c2s] = 1
                            else:
                                connections_ip6[connection_key][ack_dict_c2s][tcp.ack_nbr] = 1
                            
                            connections_ip6[connection_key][fsize_c2s] += pkt_len

                            if verbose:
                                if dst_prefix == dst and src_prefix == src:
                                    print (get_tag("n:"+str(n)), 'dupack part c2s: match ip', connection_key, src_prefix, dst_prefix, connection_key, connections_ip6[connection_key],  connections[connection_key][ack_dict_c2s][tcp.ack_nbr], pkt_len - tcp.doff*4 - hdr_len*4, pkt_len)
                        else:
                            #this is an increasing ack
                            connections_ip6[connection_key][ack_dict_c2s][tcp.ack_nbr] = 0
                            connections_ip6[connection_key][lastackseq_c2s] = tcp.ack_nbr
                            connections_ip6[connection_key][fsize_c2s] += pkt_len
                            if verbose:
                                if src_prefix == src and dst_prefix == dst:
                                    print (get_tag("n:"+str(n)), 'regular ack c->s: match ip', src_prefix, dst_prefix, connection_key, connections_ip6[connection_key], pkt_len)    
        
            #reciver side packets
            if (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port) in connections_occurences: 
                ip_pair = (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port)
                connection_key = (dst_prefix, src_prefix, tcp.dst_port, tcp.src_port, connections_occurences[ip_pair])
                
                if connection_key in connections_ip6 and (connections_ip6[connection_key][syn] == 1 and connections_ip6[connection_key][synack] == 1):

                    if pkt_len - tcp.doff*4 - hdr_len*4 > 0:
                        if tcp.seq_nbr <= connections_ip6[connection_key][lastsentseq_s2c]:
                            connections[connection_key][fsize_s2c] += pkt_len #increasing packet length
                            if tcp.seq_nbr in connections_ip6[connection_key][seq_dict_s2c]:
                                if pkt_len == connections_ip6[connection_key][seq_dict_s2c][tcp.seq_nbr]:
                                    connections_ip6[connection_key][count_s2c] = 1
                                    connections_ip6[connection_key][retx_s2c] = 1
                                    if verbose:
                                        if src_prefix == dst and sdst_prefix == src:
                                            print (get_tag("n:"+str(n)), 'match ip: retx s->c', n, src_prefix, dst_prefix, connection_key, \
                                                connections_ip6[connection_key], pkt_len - tcp.doff*4 - hdr_len*4, pkt_len)
                            else:
                                connections_ip6[connection_key][seq_dict_s2c][tcp.seq_nbr] = pkt_len

                        else:
                            connections_ip6[connection_key][fsize_s2c] += pkt_len
                            connections_ip6[connection_key][seq_dict_s2c][tcp.seq_nbr] = pkt_len
                            connections_ip6[connection_key][lastsentseq_c2s] = tcp.seq_nbr
                            if verbose:
                                if src_prefix == dst and dst_prefix == src:
                                    print (get_tag("n:"+str(n)), 'match ip: not retx s->c', src_prefix, dst_prefix, connection_key, connections_ip6[connection_key])

                    else:

                        if tcp.ack_nbr <= connections_ip6[connection_key][lastackseq_s2c]:

                            countdup += 1

                            if tcp.ack_nbr in connections_ip6[connection_key][ack_dict_s2c]:
                                connections_ip6[connection_key][ack_dict_s2c][tcp.ack_nbr] += 1
                                if connections_ip6[connection_key][ack_dict_s2c][tcp.ack_nbr] > 3:
                                   
                                    connections_ip6[connection_key][count_c2s] = 1
                                    connections_ip6[connection_key][dupack_s2c] = 1
                            else:
                                connections_ip6[connection_key][ack_dict_s2c][tcp.ack_nbr] = 1

                            connections_ip6[connection_key][fsize_s2c] += pkt_len 

                            if verbose:
                                if dst_prefix == src and src_prefix == dst:
                                    print (get_tag("n:"+str(n)), 'dupack part: match ip', connection_key, ssrc_prefix, dst_prefix, connection_key, connections_ip6[connection_key],  connections_ip6[connection_key][ack_dict_s2c][tcp.ack_nbr])    

                        else:
                            connections_ip6[connection_key][ack_dict_s2c][tcp.ack_nbr] = 0
                            connections_ip6[connection_key][lastackseq_s2c] = tcp.ack_nbr
                            connections_ip6[connection_key][fsize_s2c] += pkt_len 

                            if verbose:
                                if dst_prefix == src and src_prefix == dst:
                                    print (get_tag("n:"+str(n)), 'regular ack: match ip s->c', src_prefix, dst_prefix, connection_key, connections_ip6[connection_key],pkt_len)

if (portCombination == "ee"):
    fopen = open('completed_connection_ip4_ee.txt', 'w')
    fopen6 = open('completed_connection_ip6_ee.txt', 'w')
    startTime = time.time() #just to calculate the time of the trace parsing
    for pkt in t:
        #if (n%10000 == 0):
            #print("size", sys.getsizeof(connections), len(connections))
        tcp = pkt.tcp  #we get the tcp object
        ip = pkt.ip    #to get the ipv4 object
        #print(ip)
        ip6 = pkt.ip6 #to get the ipv6 object
        n += 1  # Wireshark uses 1-org packet numbers
        #if not tcp or not ip:
        #    continue
        if not tcp:
            if not ip6 or not ip: 
                continue
        if (tcp.src_port%2) == 0 and (tcp.dst_port%2) == 0:
            #print("hello")
            myfunction()
            #testfun()

elif (portCombination == "eo"):
    fopen = open('completed_connection_ip4_eo.txt', 'w')
    fopen6 = open('completed_connection_ip6_eo.txt', 'w')
    startTime = time.time() #just to calculate the time of the trace parsing
    for pkt in t:
        tcp = pkt.tcp  #we get the tcp object
        ip = pkt.ip    #to get the ipv4 object
        ip6 = pkt.ip6 #to get the ipv6 object
        n += 1  # Wireshark uses 1-org packet numbers
        if not tcp:
            if not ip6 or not ip: 
                continue
        if (tcp.src_port%2) == 0 and (tcp.dst_port%2) == 1:
            myfunction()

elif (portCombination == "oe"):
    #print("this is odd even")
    fopen = open('completed_connection_ip4_oe.txt', 'w')
    fopen6 = open('completed_connection_ip6_oe.txt', 'w')
    startTime = time.time() #just to calculate the time of the trace parsing
    for pkt in t:
        tcp = pkt.tcp  #we get the tcp object
        ip = pkt.ip    #to get the ipv4 object
        ip6 = pkt.ip6 #to get the ipv6 object
        n += 1  # Wireshark uses 1-org packet numbers
        if not tcp:
            if not ip6 or not ip: 
                continue
        if (tcp.src_port%2) == 1 and (tcp.dst_port%2) == 0:
            myfunction()

elif (portCombination == "oo"):
    #print("this is odd odd")
    fopen = open('completed_connection_ip4_oo.txt', 'w')
    fopen6 = open('completed_connection_ip6_oo.txt', 'w')
    startTime = time.time() #just to calculate the time of the trace parsing
    for pkt in t:
        tcp = pkt.tcp  #we get the tcp object
        ip = pkt.ip    #to get the ipv4 object
        ip6 = pkt.ip6 #to get the ipv6 object
        n += 1  # Wireshark uses 1-org packet numbers
        if not tcp:
            if not ip6 or not ip: 
                continue
        if (tcp.src_port%2) == 1 and (tcp.dst_port%2) == 1:
            myfunction()
            #testfun()

else:
    print("Not a valid port combination")
    exit()

with open('conn_occ'+'_'+portCombination, 'w') as f:
    for key, value in connections_occurences.items():
        f.write (str(key) + " : " + str(value) + "\n" )

with open('conn_ipv4'+'_'+portCombination, 'w') as f:
    for key, value in connections.items():
        f.write (str(key) + " : " + str(value) + "\n" )
        
with open('conn_ipv6'+'_'+portCombination, 'w') as f:
    for key, value in connections_ip6.items():
        f.write (str(key) + " : " + str(value) + "\n" )

with open('json_output', 'w') as f:
    for key, value in json_output.items():
        f.write (str(key) + " : " + str(value) + "\n" )



print ("Time needed: ", time.time() - startTime)

print(len(connections), len(connections_ip6), len(connections_occurences))
print("count =", count, "countrtx =", countrtx, "countdup =", countdup)
print("Total completed connections =", countcc)
t.close()  # Don't do this inside the loop!