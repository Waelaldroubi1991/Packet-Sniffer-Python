
#Student Name: Wael Aldroubi
#Student ID:   300456658

#..............................................................................................................

#python libraries needed
import binascii
import struct
import sys
import ipaddress
import string
from pcapy import pcapy
from helper import *

#..............................................................................................................

class PacketHeaderBase:
    #function to create headers from the data.
    #to divide data into headers so we can analysis them.
    def __init__(raw, header_form, field_name, data):
        raw.data = data
        raw.hdr_length = struct.calcsize(header_form)
        raw.field_values = struct.unpack(
            header_form, 
            data[:raw.hdr_length])
        raw.payload = data[raw.hdr_length:]
        pkt_dict = dict(zip(field_name, raw.field_values))
        for k, v in pkt_dict.items():
            setattr(raw, k, v)

#..............................................................................................................
                
class Ethernet(PacketHeaderBase):
    # 6 Bytes for destination address, another 6 Bytes for source address and 2 Bytes for type
    form = '6s6s2s'  
    field = ['dest','src','type'] 
    # function to take data from ethernet frame.
    def __init__(raw, data):
        super().__init__(Ethernet.form, Ethernet.field, data) 
        #to check the type using process packet function.
        global IP_TYPE;
        #assigning values
        IP_TYPE = mac2str(raw.type ) 
        raw.dest_mac = mac2str(raw.dest)
        raw.src_mac = mac2str(raw.src)
        #prints out the Source and Destination MAC addresses
        print("Src mac: {}".format(raw.src_mac))
        print("Dst mac: {}".format(raw.dest_mac))
        #this will print the original data
        def __str__(self):
        return "Ethernet payload {}".format(decode_payload(self.payload))

#..............................................................................................................

class IPV4(PacketHeaderBase):
    #Byte for (verson/DSCP/Tll), 2 Bytes for (length/identification/flags+offset/checksum) and 4 Bytes for source ip and destination ip
    form = 'ss2s2s2sss2s4s4s' 
    field = ['version_IHL','DSCP+ECN','length','identification','flags + offset','tll','protocol','checksum','src_ip','dst_ip']  
    # function to take data from IPV4.
    def __init__(raw, data):
        super().__init__(IPV4.form, IPV4.field, data)
        #to check the type using process packet function.
        global PROTOCOL_TYPE; 
        PROTOCOL_TYPE = mac2str(raw.protocol)
        #prints out the Source and Destination IP addresses
        print("Ether Type: IPv4")
        print("   From: {}".format(ipaddress.IPv4Address(raw.src_ip)))
        print("   To: {}".format(ipaddress.IPv4Address(raw.dst_ip)))
        #this will print the original data
        def __str__(self):
        return "IPV4 payload {}".format(decode_payload(self.payload))

#..............................................................................................................

class IPV6(PacketHeaderBase):
	#4 Bytes for version 2 Bytes for payload 1 Byte for next header and hop limit and then 16 Bytes for source ip and destination ip
    form = '4s2sss16s16s'  
    field = ['version_class_label','payloadlength', 'next_header','hoplimit','source', 'dest']
    # function to take data from IPV6.
    def __init__(raw, data):
        super().__init__(IPV6.form, IPV6.field, data)
        #to check the type using process packet function.
        global PROTOCOL_TYPE;  
        raw.protocol = mac2str(raw.next_header)
        PROTOCOL_TYPE = raw.protocol
        #prints out the Source and Destination IP addresses
        print("Ether Type: IPv6")
        print("   From: {}".format(ipaddress.IPv6Address(raw.source)))
        print("   To: {}".format(ipaddress.IPv6Address(raw.dest)))
       	#this will print the original data
    	def __str__(raw):
        return "IPV6 payload {}".format(decode_payload(raw.payload))

#..............................................................................................................

class ARP(PacketHeaderBase):
	#2 bytes for hardware type 2 bytes for protocol 1 bytes for address length and protocol length 2 bytes for operations 6 bytes for MAC address and 4 bytes for IP address for both source and destination 
    form = '2s2sss2s6s4s6s4s'  
    field = ['hardware_type','protocol','hardware_address_len','protocol_len','opcode','sender_mac','sender_ip','target_mac','target_ip'] 
    # function to check if the packet is ARP and print it, ARP is Address Resolution Protocol a network layer protocol used to convert an IP address into a physical address
    def __init__(raw, data):
        super().__init__(ARP.form, ARP.field, data)
        raw.dest_ip = mac2str(raw.target_ip)
        raw.source_ip = mac2str(raw.sender_ip)
        #converts the IP address and print it for both source and destination
        print("Ether Type: ARP")
        print("   From: {}".format(hex2ip(raw.dest_ip.replace(":","")))) #Converts it to an IP format as there's no in built function in python
        print("   To: {}".format(hex2ip(raw.source_ip.replace(":","")))) #that formats ARP addresses 
        #this will print the original data
    	def __str__(raw):
        return "{}".format(decode_payload(raw.payload))

#..............................................................................................................

class TCP(PacketHeaderBase):
	#2 bytes for source and destination 4 bytes for sequence number and ACK 2 bytes for data offset and window size and 4 bytes for checksum and pointer.
    form = '2s2s4s4s2s2s4s'  
    field = ['src_port','dst_port','seq_num','ACK','data_offset','win_size','checksum+pointer']
    # function to take data from TCP.
    def __init__(raw, data):
        super().__init__(TCP.form, TCP.field, data)
        #reading source and destination ports
        raw.source = mac2str(raw.src_port)
        raw.dest = mac2str(raw.dst_port)
        # get Data offset and convert it to int
        header_len = int ((binascii.hexlify(raw.data_offset).decode('ascii')[:1]),16 )
        #calculate the length of the header
        raw.hdr_length =(header_len * 4 )
        raw.payload = data[raw.hdr_length:]
        # print the data
        print("Protocol: TCP")
        print("Src port: {}".format(int(raw.source.replace(":",""),16)))
        print("Dst port: {}".format(int(raw.dest.replace(":",""),16))) 
        print("Payload({} bytes)".format(len(raw.payload)))
        #this will print the original data
    	def __str__(raw):
        return "{}".format(decode_payload(raw.payload)) 

#..............................................................................................................
      
class UDP(PacketHeaderBase):
	#2 bytes for all of source and destionation ports, length and checksum + the pointer
    form = '2s2s2s2s'  
    field = ['src_port','dst_port','length','checksum+pointer'] 
    # function to take data from UDP.
    def __init__(raw, data):
        super().__init__(UDP.form, UDP.field, data)
        #reading source and destination ports
        raw.source = mac2str(raw.src_port)
        raw.dest = mac2str(raw.dst_port)
        # print the data
        print("Protocol: UDP")
        print("Src port: {}".format(int(raw.source.replace(":",""),16)))
        print("Dst port: {}".format(int(raw.dest.replace(":",""), 16)))
        print("Payload({} bytes)".format(len(raw.payload)))
        #this will print the original data
    	def __str__(raw):
        return "{}".format(decode_payload(raw.payload))

#..............................................................................................................

class ICMP(PacketHeaderBase):
  	#1 bytes for type and code and 2 bytes for checksum and 4 bytes for rest of the header 
    form = 'ss2s4s'  
    field = ['type','code','checksum','restOfHeader'] 
    # function to take data from ICMP.
    def __init__(raw, data):
        super().__init__(ICMP.form, ICMP.field, data)
        raw.typ = mac2str(raw.type)
        # print the data
        print("Protocol: ICMP")
        print("Type: {}".format(int(raw.typ,16))) 
        print("Payload({} bytes)".format(len(raw.payload)))
        #this will print the original data
    	def __str__(raw):
        return "{}".format(decode_payload(raw.payload))

#..............................................................................................................

class UNKNOWN(PacketHeaderBase):
    #this function is for unknown packets, will print the original data as no information is clear about its type   
    def __init__(raw, data):
       print("Protocol: Unknown")
       print("This protocol is not defined. Payload is shown below")

#..............................................................................................................      

#this function is to process each packet and it will be called in a loop in the main function to process all data during open session.
#it will check the type in the header and convert streams of data into human readable information.
#using protocol number to decide which kind it is (for protocol number : https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
def process_packet(packet_data):
    parsed_packet = dict()
    parsed_packet['ethernet'] = Ethernet(packet_data)
    #this section when data are of IPV4 kind
    #check if data is IPV4
    if IP_TYPE == '08:00': 
       parsed_packet['IPV4'] = IPV4( parsed_packet['ethernet'].payload)
       #check if data is UDP
       if PROTOCOL_TYPE == '11': 
         parsed_packet['UDP'] = UDP( parsed_packet['IPV4'].payload)
         print("\n{}".format(hexdump(str(parsed_packet['UDP']))))
         #check if data is TCP
       elif PROTOCOL_TYPE == '06':
         parsed_packet['TCP'] = TCP(parsed_packet['IPV4'].payload)
         print("\n{}".format(hexdump(str(parsed_packet['TCP']))))
         #check if data is ICMP
       elif PROTOCOL_TYPE  == '01':
         parsed_packet['ICMP'] = ICMP( parsed_packet['IPV4'].payload)
         print("\n{}".format(hexdump(str(parsed_packet['ICMP']))))
       else: 					     
       	#check if data is unknown
       	parsed_packet['UNKNOWN'] = UNKNOWN(parsed_packet['IPV4'].payload) 
       	print("Payload({} bytes)".format(len(parsed_packet['IPV4'].payload)))
        print("\n{}".format(hexdump(decode_payload(parsed_packet['IPV4'].payload)))) 
        #this section when data are of IPV6 kind
        #check if data is IPV6
    elif IP_TYPE  == '86:dd':
       parsed_packet['IPV6'] = IPV6(parsed_packet['ethernet'].payload)
       #check if data is UDP
       if PROTOCOL_TYPE == '11':
         parsed_packet['UDP'] = UDP(parsed_packet['IPV6'].payload)
         print("\n{}".format(hexdump(str(parsed_packet['UDP']))))
         #check if data is TCP
       elif PROTOCOL_TYPE == '06':
         parsed_packet['TCP'] = TCP(parsed_packet['IPV6'].payload)
         print("\n{}".format(hexdump(str(parsed_packet['TCP'])))) 
         #check if data is ICMP
       if PROTOCOL_TYPE == '3a':	
         parsed_packet['ICMP'] = ICMP(parsed_packet['IPV6'].payload)
         print("\n{}".format(hexdump(str(parsed_packet['ICMP']))))
       else: 
       	#check if data is unknown
       	 parsed_packet['UNKNOWN'] = UNKNOWN(parsed_packet['IPV6'].payload)
         print("\n{}".format(hexdump(decode_payload(parsed_packet['IPV6'].payload)))) 
         print("Payload({} bytes)".format(len(parsed_packet['IPV6'].payload)))
         #check if data is ARP
    elif IP_TYPE  == '08:06': 
       parsed_packet['ARP'] = ARP(parsed_packet['ethernet'].payload)  
       print("\n{}".format(hexdump(str(parsed_packet['ARP']))))
       #or it will be unknown to any format
    else:
       parsed_packet['UNKNOWN'] = UNKNOWN(parsed_packet['ethernet'].payload)
       print("Payload({} bytes)".format(len(parsed_packet['ethernet'].payload)))
       print("\n{}".format(hexdump(decode_payload(parsed_packet['ethernet'].payload))))

#..............................................................................................................
#this code is from blackboard, from this module page.
#main function, will call process packet and call it in an infinte loop to read the data and analysis it to get its type and make it human readable.
def main(pcap_filename):
    #will read our file
    print( "Opening file: '{}'".format(pcap_filename) )
    pcap_reader = pcapy.open_offline( pcap_filename )
    # loop to take stream of data
    count = 0
    while True:
        meta, data = pcap_reader.next()
        if len(data) < 1:
            break  
        #will call process packet function and read the data in our file
        count += 1
        print("#### Packet {}:".format(count))
        process_packet( data )
    print("Complete. {} packets processed.".format(count))
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please supply pcap file argument: python3 sniffer.py packets.pcap")
        exit()
    main(sys.argv[1])
#..............................................................................................................
