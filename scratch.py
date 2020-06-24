#!/usr/bin/sudo python


import argparse
import datetime
import signal
import time


import scapy
from scapy.all import *



import rb_netflow as rbnf

signal_received = 0


def preexec():
    os.setpgrp()  # Don't forward signals


def signal_handler(signal, frame):
    global signal_received
    signal_received = 1


def main():
    if os.getuid() != 0:
        print "You need to be root to run this, sorry."
        return

    parser = argparse.ArgumentParser(description='UDP packets producer with scapy')
    parser.add_argument('-s', '--source-ip', dest='src_ip',
                        help='IP source')
    parser.add_argument('-sp', '--source-port', dest='src_port',
                        help='Port dst')
    parser.add_argument('-d', '--dst-ip', dest='dst_ip',
                        help='IP source')
    parser.add_argument('-dp', '--dst-port', dest='dst_port',
                        help='Port dst')
    parser.add_argument('-t', '--time-interval', dest='time_interval',
                        help='Time interval to wait to send other messages.')

    args = parser.parse_args()

    if args.src_ip:
        IP_SRC = args.src_ip
    else:
        IP_SRC = "10.0.203.2"

    IP_DST = "172.16.27.180"

    if args.src_port:
        PORT_SRC = int(args.src_port)
    else:
        PORT_SRC = int(2056)

    if args.time_interval:
        TIME_INTERVAL = args.time_interval
    else:
        TIME_INTERVAL = 0

    if args.dst_port:
        PORT_DST = int(args.dst_port)
    else:
        PORT_DST = int(2055)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Current timestamp in seconds
    tnow = (datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).seconds

    # Netflow5
    nfh = rbnf.NetflowHeader(version=5)
    # No need the count field! see rb_netflow.py:post_build
    nf5h = rbnf.NetflowHeaderV5( \
        sysUptime=0x3e80, \
        unixSecs=tnow, \
        unixNanoSeconds=0x04bdb6f0, \
        flowSequence=48, \
        engineType=0, \
        engineID=0, \
        samplingInterval=0)

    # wireshark File -> export specified packet dissections -> as plain text

    records = [
        rbnf.NetflowRecordV5( \
            src="192.168.0.17", dst="8.8.8.8", nexthop="0.0.0.0", \
            input=0, output=0, dpkts=1, dOctets=72, \
            first=1, last=2, srcport=49622, \
            dstport=53, pad1=0, tcpFlags=0x00, \
            prot=17, tos=0x00, src_as=0, dst_as=0, \
            src_mask=0, dst_mask=0, pad2=0),
    ]

    data = IP(dst=IP_DST) / UDP(dport=PORT_DST) / nfh / nf5h
    for r in records:
        data /= r

    wrpcap('5.pcap', data)

    send(data)

    while TIME_INTERVAL is not 0:
        if signal_received == 1:
            print "\nSignal received. Stopping and Exitting..."
            sys.exit(0)
        time.sleep(float(TIME_INTERVAL))
        send(data)


if __name__ == '__main__':
    main()
