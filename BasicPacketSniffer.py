#Must run file as root in order to work
import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '

def main(): #v 1)used to receive and send raw packets 2)for raw network protocol access 3)makes sure that byte order is correct to read v
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True: #v socket called "connection" takes all received data and stores in two variables v
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        #8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL:{}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            #ICMP
            if proto == 1:
                (icmp_type, code, checksum, data[4:]) = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum:{}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
            #TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
            #UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_packet(data)
                print(TAB_1 + 'Data:')
                print(TAB_2 + 'Source Port : {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
            #Other
            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print('Data:')
            print(format_multi_line(DATA_TAB_2, data))

#Unpack Ethernet Frame                  vv Dest + Src + Type of Ethernet Frame vv
def ethernet_frame(data):              #v 6bytes+6bytes+2bytes v <=First 14 bytes
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] #Last argument is rest of data
                                                                       # ^ Ethernet Protocol

#Return properly formatted MAC address (i.e. AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr) #<= takes the chunks of MAC address (i.e. AA) making sure only 2 decimal places for each one
    return ':'.join(bytes_str).upper() #<= joining all those MAC addresses with colons and capitalizing

#Unpacks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4 #take byte and bit-shift 4 to the right leaving only version number
    header_length = (version_header_length & 15) * 4 #HL used to determine where data starts
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) #IPv4 Header is 20 Byters long
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]
                                                                    #^ rest of the data beyond end of HL

#Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))
                       # ^ taking all addr chunks and mapping to str
          # ^ joins all strings to look like '127.0.0.1'

#Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]
          #{   beginning of data   }  {  end  }

#Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags) >> 12 * 4
                   # ^ TCP chunk is 16 bits, so bit-shit chunk 12 bits to right to isolate offset
    flag_urg = (offset_reserved_flags & 32) * 5
    flag_ack = (offset_reserved_flags & 16) * 4
    flag_psh = (offset_reserved_flags & 8) * 3
    flag_rst = (offset_reserved_flags & 4) * 2
    flag_syn = (offset_reserved_flags & 2) * 1
    flag_fin = offset_reserved_flags & 1                    #actual data (ex HTTP requests) starting from offset and beyond vv
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpacks UDP packet
def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]
          #{   beginning of data   }  {  end  }

#Found on internet the formats multi-line data; breaks it up line by line and makes it human-readable
def format_multi_line(prefix, string, size=80):
    size-= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02X}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
    main()