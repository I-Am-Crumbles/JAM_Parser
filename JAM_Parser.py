#! /usr/bin/python3

#imported libraries

import sys
import argparse
import os
from scapy.all import *
from collections import Counter
from prettytable import PrettyTable
import string


# The main function that opens the pcap file, A print statetment also displays letting the user know what file they chose to work with.
def parse_pcap(file_name):
    print(f"Opening {file_name}")

# The following Block of code  defines the user input options  and provides help menu information

# Dunder Check
if __name__ == '__main__':
    #The argparse library is how we will add the flags the user will input. The following line opens the ArgumentParser module and sets it to a variable. It also enables the help menu argument and provides a brief description of the the scripts purpose. 
    parser = argparse.ArgumentParser(description="PCAP reader that will automatically parse data and output into a table. ", add_help=True)
    # this line of code adds the -pcap flag, we set the action to "store_true" so that the script will remember the user input it and continue to search for other flags instead of ending when it finds one. *all of the following arguments will contain this "action". We won't require the user input any single flag so that is set to false. Help information is also entered on this line.
    parser.add_argument('-pcap','--pcap', action = 'store_true',
            help='Opens Packet Capture to be parsed', required = False)
    # This is the -IP flag and help information. It will output all of the Source and Destination IP addresses and their counts into a table. 
    parser.add_argument('-IP', action = 'store_true',
            help='Displays a table of source and destination IP addresses', required = False)
    #Sets the arguments the user enters to a variable to be used later. Since the first argument position is the script and the last one is the pcap/ng file we are opening we are ignoring those positions.
    args = parser.parse_args(sys.argv[1:-1])
    # defines the parameter of the parse_pcap functions to be the last argument the user enters, which should be the file they wish to parse
    file_name = sys.argv[-1]
    # if check to make sure that the file the user entered exists on the system.
    if not os.path.isfile(file_name):
        # if the file doesn't exist the script will output a print statement telling the user so
        print(f"{file_name} does not exist")
        #Causes to the script to exit in the event that the file input was not found.
        sys.exit(-1)

    # if check to see if the user input -the pcacp flag as an argument if they did it will open and parse through the pcap file and output interesting information **Interesting information check to be added
    if args.pcap:
        parse_pcap(file_name)


# From this point on Using scapy the script will read through the pcap/ng file that the "file_name" variable above was set to and then attempt to iterate through each packet and store 5 tuple and other useful information into categorized lists that will also be put into a table using the PrettyTable library. User input will determine which tables print based on the flags they enter as arguments.

#Sets all of the packets found in the open pcap file temporarily to a variable called "packets" to be itterated through to search for 5 tuple information using for loops.
packets = rdpcap(file_name)
# The following lines of code are the variables each of the lists of useful information will be set to.
srcIP=[]
dstIP=[]
tcpsrc =[]
tcpdst =[]
udpsrc =[]
udpdst =[]
dnsport =[]
smtpport =[]

#This for loop will be utilized through out this section of code, although the variable names will be slightly different the idea is the same for each step. The first one here will itterate through each individual packet in the packets variable and pull out source IP addreses that get input into a list
for pkt in packets:
    # if check to see if the IP variable can be found in the packet
    if IP in pkt:
        # if it finds an ip address it will try to find and append the source ip address to the list variable above
        try:
            srcIP.append(pkt[IP].src)
        #if it can't find a source ip to append to the list it will exit the for loop and move on to the rest of the code
        except:
            pass
# using the counter module from the collections module we will have a for loop itterate through our list and count each individual IP addresses number of occurances and store that data as a dictionary under the variable "cnt" 
cnt = Counter()
for ip in srcIP:
    cnt[ip] += 1

# We will then use the PrettyTable library to output the data above into a table saved to a variable that can be printed out based on user input 

# sets the table to a variable and labels the columns
table1= PrettyTable(["SRC.IP", "Count"])
#For loop to iterrate through the dictionary and pull the ip address and it's count from it
for ip, count in cnt.most_common():
    # adds the ip address and it's count as a row in the table
    table1.add_row([ip, count])
#print(table1)    

# this code block does the same as above but instead it will search through packets looking for TCP protocal information and storing the port numbers used and the number of occurences 
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

# This code block is used to find and table Destination IP addresses and their count.
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

#This code block is used to find and table destination TCP ports and their counts
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

#This code block is used to find and table source UDP ports and their counts
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

# This code block is used to find and table destination UDP ports and their count
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

#The following two code blocks are intended to find and table DNS traffic however this feature does not currently work
'''
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
'''
# The following section of code will check the flags the user input and then print the corresponding tables if the lists associated with that table have any information in them.

#if check to see if the -IP flag was input by the user and if it was we proceed to the next if check
if args.IP:
    #here we check to make sure that the list associated with the table contains data and if it does we print the table
    if srcIP:
        print(table1)
    # if the list was empty the script will exit the for loop and continue    
    else:
        pass
    # The -Ip flag also attemps to print the destination IP table if the list associate with it is not empty.
    if dstIP:
        print(table3)
    else:
        pass

# partial print statements for tables that have yet to have a user input flag created for them. 
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

#Table 7 "DNS Traffic" does not currently work
if dnsport:
    print(table7)
else: 
    pass
'''

# the following lines of code are a work in progress 

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

