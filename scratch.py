#!/usr/bin/python2


import argparse
import signal,sys
import time



import scapy
from scapy.all import *
from scapy.all import sniff
from scapy.all import IP
from scapy.all import DNSQR
from scapy.all import UDP
from scapy.all import TCP
from scapy.all import DNS
from datetime import datetime

import rb_netflow as rbnf

IP_DST='0.0.0.0'
PORT_SRC=5000
PORT_DST=2055
sampling_rate=5
buffer_count=10
records = []  # Array containing records to be sent
records_in_buffer = 0  # Counts records to be stored before sending them
packet_count_for_sampling = 0  # Counts packets before sampling occurs
flow_Sequence=1


class GracefulKiller:
  kill_now = False
  def __init__(self):
    signal.signal(signal.SIGINT, self.exit_gracefully)
    signal.signal(signal.SIGTERM, self.exit_gracefully)

  def exit_gracefully(self,signum, frame):
    self.kill_now = True



def send_to_collector(records_to_send):
    global IP_DST,IP_SRC,PORT_SRC,PORT_DST,flow_Sequence
    s = conf.L2socket()
    # Current timestamp in seconds
    tnow = int((datetime.utcnow()-datetime(1970,1,1)).total_seconds())
    # Netflow5
    nfh = rbnf.NetflowHeader(version=5)
    # No need the count field! see rb_netflow.py:post_build
    nf5h = rbnf.NetflowHeaderV5( \
        sysUptime=0x3e80, \
        unixSecs=tnow, \
        unixNanoSeconds=0x04bdb6f0, \
        flowSequence=flow_Sequence, \
        engineType=1, \
        engineID=0, \
        samplingInterval=10)

    # in case no IP Source is provided leave it blank, so send will detect..
    try:
        data = IP(src=IP_SRC,dst=IP_DST) / UDP(sport=PORT_SRC,dport=PORT_DST) / nfh / nf5h
    except:
        data = IP(dst=IP_DST) / UDP(sport=PORT_SRC, dport=PORT_DST) / nfh / nf5h

    #print data[0].show()
    for r in records_to_send:
        data /= r
    sys.stdout.write('.')
    s.send(data)
    flow_Sequence+=1

def process(pkt):
    global records,sampling_rate,buffer_count,records_in_buffer,packet_count_for_sampling
    if pkt.haslayer(DNSQR) and UDP in pkt and pkt[UDP].sport == 53:
        for i in range(0, pkt[DNS].ancount):
            name = pkt[DNS].an[i].rrname
            solved = pkt[DNS].an[i].rdata
            tpe = pkt[DNS].an[i].type
            now = datetime.now()
            data = {'Domain': name, 'IP': solved, 'Type': tpe, 'occurrence': 1, 'Last_seen': datetime.now()}
            #print name, '   ', solved, '  ', tpe
    packet_count_for_sampling+=1
    if packet_count_for_sampling==sampling_rate:
        if TCP in pkt:
            flgs=pkt[TCP].flags
        else:
            flgs=''
        records.append(
            rbnf.NetflowRecordV5( \
                src=pkt[IP].src, dst=pkt[IP].dst, nexthop="192.168.1.1", \
                input=100, output=200, dpkts=1, dOctets=pkt[IP].len, \
                first=1, last=2, srcport=pkt[IP].sport, \
                dstport=pkt[IP].dport, pad1=0, tcpFlags=flgs, \
                prot=pkt[IP].proto , tos=0x00, src_as=0, dst_as=0, \
                src_mask=0, dst_mask=0, pad2=0),
        )
        records_in_buffer+=1
        if records_in_buffer==int(buffer_count):
            send_to_collector(records)
            records_in_buffer=0
            records=[]
        packet_count_for_sampling=0


def main():
    global IP_DST,IP_SRC,PORT_SRC,PORT_DST,sampling_rate,buffer_count
    if os.getuid() != 0:
        print "You need to be root to run this, sorry."
        return

    parser = argparse.ArgumentParser(description='Netflow generator for laptops')
    parser.add_argument('-i', '--interface', dest='int',
                        help='Monitored interface')
    parser.add_argument('-s', '--source', dest='src_ip',
                        help='Source IP address. Used to send packets to collector')
    parser.add_argument('-sp', '--sport', dest='src_port',
                        help='Source port. Used to send packets to collector. Default 5000')
    parser.add_argument('-d', '--destination', dest='dst_ip',
                        help='Destination IP address. Used to send packets to collector')
    parser.add_argument('-dp', '--dport', dest='dst_port',
                        help='Destination port. Used to send packets to collector. Default 2055')
    parser.add_argument('-r', '--rate', dest='sampling_rate',
                        help='Sampling 1 out of r packets. Default 5')
    parser.add_argument('-b', '--buffer', dest='buffer_count',
                        help='Number of packets stored in buffer before sending them. Default 10')

    args = parser.parse_args()

    if not args.src_ip:
        print "Source IP Address not provided....trying to get interface IP Address"
    else:
        IP_SRC=args.src_ip
    if not args.dst_ip:
        print "Destination IP Address is mandatory. Aborting..."
        exit()
    else:
        IP_DST=args.dst_ip
    if not args.int:
        print "Monitored interface is mandatory. Aborting..."
        exit()
    else:
        IP_INT=args.int
    if not args.src_port:
        PORT_SRC=int(5000)
    else:
        PORT_SRC=int(args.src_port)
    if not args.dst_port:
        PORT_DST=int(2055)
    else:
        PORT_DST=int(args.dst_port)

    if args.dst_port:
        PORT_DST = int(args.dst_port)
    else:
        PORT_DST = int(2055)

    if not args.sampling_rate:
        sampling_rate=5
    else:
        sampling_rate=int(args.sampling_rate)

    if not args.buffer_count:
        buffer_count=int(10)
    else:
        buffer_count=int(args.buffer_count)




    sn=AsyncSniffer(iface=IP_INT,filter='ip and (udp or tcp)', prn=process, store=0)
    sn.start()


if __name__ == '__main__':
    killer = GracefulKiller()
    while not killer.kill_now:
        time.sleep(1)
        main()
