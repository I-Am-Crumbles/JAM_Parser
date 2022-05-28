# Jam_Parser
Final Project for Fullstack Academy. Objective is to Create a tool that parses through a pcap file and automatically extracts key data using python.

And we present to you the JAM_Parser...(presentation to come)

The JAM_Parser will automatically parse through pcap and pcapng files and output relavent five tuple data. It will also sort and table that data based on user input argument flags.

**It should be noted that in it's current version the JAM_Parser REQUIRES that the last argument be a file name

Example Usage:

              ./JAM_Parser.py [-h] [-pcap] [-all] [-MAC] [-IP] [-TCP] [-UDP] [-ICMP] [-DNS] <file_name>
              
Flags:

      [-h]: Displays help message and exits
      
      [-pcap]: Opens packet capture to be parsed and lists any useful 5 tuple information found in the packets
      
      [-all]: Outputs all tabled data found by JAM_Parser
      
      [-MAC]: Displays tables containing source and destination MAC addresses and the number of packets containing each of them
      
      [-IP]: Displays tables containing source and destination IP addresses and the number of packets containing each of them
      
      [-TCP]: Displays tables containing source and destination TCP ports and the number of packets containing each of them
      
      [-UDP]: Displays tables containing source and destination UDP ports and the number of packets containing each of them
      
      [-ICMP]: Displays tables containing ICMP traffic source and destination ports and the number of packets containing them
      
      [-DNS]: Displays tables containg DNS traffic and the number of packets each query shows up in.
     
     
 
