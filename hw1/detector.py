import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str

# RELEVANT TCP CONTROL FLAGS from tcp.py (dpkt)
TH_SYN = 0x02  # synchronize sequence numbers
TH_ACK = 0x10  # acknowledgment number set


def print_packets(pcap):
    sourceSYN = {} # counts the number of times an IP sent a SYN
    destSYNACK = {} # counts the number of times an IP received a SYNACK
    
    for timestamp, buf in pcap:
        # first thing we want to do is make sure we're usign Ethernet, IP, and TCP
        try: 
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            # print('Non Ethernet Packet type not supported')
            continue
        
        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            # print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        ip = eth.data

        # now we ensure that the packet is TCP
        if isinstance(ip.data, dpkt.tcp.TCP): 
            tcp = ip.data
            # print("hit in here")

            # if we are sending a SYN flag (and not ACK), then we increment
            if ( (tcp.flags & TH_SYN) and not (tcp.flags & TH_ACK) ): 
                sourceSYN[inet_to_str(ip.src)] = sourceSYN.get(inet_to_str(ip.src), 0) + 1
                
            # if we are sending SYN and ACK then we also increment
            if ( (tcp.flags & TH_SYN) and (tcp.flags & TH_ACK) ): 
                destSYNACK[inet_to_str(ip.dst)] = destSYNACK.get(inet_to_str(ip.dst), 0) + 1


    # computation to check if we are a scanner: 
    for inet, packets in sourceSYN.items():
        # note that if we don't see our inet in our detsSYNACK, then
        # we just assume its 0 (makes sense)
        if ( 3 * destSYNACK.get(inet, 0) < packets ): 
            print(inet)

    # correct = ["128.3.23.2",
    #             "128.3.23.5",
    #             "128.3.23.117",
    #             "128.3.23.158",
    #             "128.3.164.248",
    #             "128.3.164.249"]

    # print("printing solution: ")
    # for ip in correct: 
    #     print( sourceSYN.get(ip, 0) )
    #     print( destSYNACK.get(ip, 0) )



def test():
    """Open up a test pcap file and look for scanning inets"""
    with open('part2.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)


if __name__ == '__main__':
    test()