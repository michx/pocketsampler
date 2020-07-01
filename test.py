from pylibpcap.pcap import sniff


for plen, t, buf in sniff("en0", filters="ip and (udp or tcp)", count=-1, promisc=1):
    print("[+]: Payload len=", plen)
    print("[+]: Time", t)
    print("[+]: Payload", buf)
