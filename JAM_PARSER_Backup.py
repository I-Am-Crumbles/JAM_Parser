#! /usr/bin/python3

import sys
import argparse
import os
from scapy.all import *
from collections import Counter
from prettytable import PrettyTable
import string



def parse_pcap(file_name):
    print(f"Opening {file_name}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PCAP reader that will automatically parse data and output into a table. ", add_help=True)
    parser.add_argument('-pcap','--pcap', action = 'store_true',
            help='Opens Packet Capture to be parsed', required = False)
    parser.add_argument('-IP', action = 'store_true',
            help='Displays a table of source and destination IP addresses', required = False)
    args = parser.parse_args(sys.argv[1:-1])

    file_name = sys.argv[-1]
    if not os.path.isfile(file_name):
        print(f"{file_name} does not exist")
        sys.exit(-1)
    if args.pcap:
        parse_pcap(file_name)

packets = rdpcap(file_name)
srcIP=[]
dstIP=[]
tcpsrc =[]
tcpdst =[]
udpsrc =[]
udpdst =[]
dnsport =[]
smtpport =[]
for pkt in packets:
    if IP in pkt:
        try:
            srcIP.append(pkt[IP].src)
        except:
            pass

cnt = Counter()
for ip in srcIP:
    cnt[ip] += 1

table1= PrettyTable(["SRC.IP", "Count"])
for ip, count in cnt.most_common():
    table1.add_row([ip, count])
#print(table1)    

for pkt in packets:
    if TCP in pkt:
        try:
            tcpsrc.append(pkt[TCP].sport)
        except:
            pass
cnt2 = Counter()
for port in tcpsrc:
    cnt2[port] +=1

table2 = PrettyTable(["TCP SRC PORT", "Count"])
for port, count in cnt2.most_common():
    table2.add_row([port, count])
#print(table2)

for pkt in packets:
    if IP in pkt:
        try:
            dstIP.append(pkt[IP].dst)
        except:
            pass

cnt3 = Counter()
for ip in dstIP:
    cnt3[ip] += 1

table3 = PrettyTable(["DST.IP", "Count"])
for ip, count in cnt3.most_common():
    table3.add_row([ip, count])
#print(table3)

for pkt in packets:
    if TCP in pkt:
        try:
            tcpdst.append(pkt[TCP].dport)
        except:
            pass
cnt4 = Counter()
for port in tcpdst:
    cnt4[port] +=1

table4 = PrettyTable(["TCP DST PORT", "Count"])
for port, count in cnt4.most_common():
    table4.add_row([port, count])
#print(table4)

for pkt in packets:
    if UDP in pkt:
        try:
            udpsrc.append(pkt[UDP].sport)
        except:
            pass
cnt5 = Counter()
for port in udpsrc:
    cnt5[port] +=1

table5= PrettyTable(["UDP SRC PORT", "Count"])
for port, count in cnt5.most_common():
    table5.add_row([port, count])
#print(table5)

for pkt in packets:
    if UDP in pkt:
        try:
            udpdst.append(pkt[UDP].dport)
        except:
            pass
cnt6 = Counter()
for port in udpdst:
    cnt6[port] += 1

table6 = PrettyTable(["UDP DST PORT", "Count"])
for port, count in cnt6.most_common():
    table6.add_row([port, count])

for pkt in packets:
    if DNS in pkt:
        try:
            dnsport.append(pkt[DNS].sport)
        except:
            pass
cnt7 = Counter()
for port in dnsport:
    cnt7[port] +=1

table7 = PrettyTable(["DNS TRAFFIC", "Count"])
for port, count in cnt7.most_common():
    table7.add_row([port, count])

if args.IP:
    if srcIP:
        print(table1)
    else:
        pass
    if dstIP:
        print(table3)
    else:
        pass
'''
if tcpsrc:
    print(table2)
else:
    pass
if tcpdst:
    print(table4)
else:
    pass
if udpsrc:
    print(table5)
else:
    pass
if udpdst:
    print(table6)
else:
    pass
if dnsport:
    print(table7)
else: 
    pass
'''

'''
columns = ["IP.src", "Count"]
Master_table = PrettyTable()
for ip, count in cnt.most_common():
    Master_table.add_column(columns[0], [ip])
for ip, count in cnt.most_common():
    Master_table.add_column(columns[1],  [count])
print(Master_table)
'''

'''
print(cnt.most_common)
for ip, count in cnt.most_common():
    print(ip)
for ip, count in cnt.most_common():
    print(count)
''' 
'''
print(cnt)
ip_dst_table = PrettyTable()
for c in string.ascii_uppercase:
    ip_dst_table.add_column(c, [])
for dct in cnt.most_common:
    ip_dst_table.add_row([dct.get(c, "") for c in string.ascii_uppercase])
print(ip_dst_table)
'''    