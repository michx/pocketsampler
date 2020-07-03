# Pocketsampler

This is a simple Flow Generator. It captures traffic from desired interface and creates flow samples to be sent to a desired collector.
It uses scapy and libpcap libraries.


## Before installing

The script requires libpcap source libraries:

<i>sudo apt install libpcap-dev</i>


## Installation

<i>pip install -r requirements.txt</i>


## Usage

You can find help inline, as below.

usage: scratch.py [-h] [-i INT] [-s SRC_IP] [-sp SRC_PORT] [-d DST_IP]
                  [-dp DST_PORT] [-r SAMPLING_RATE] [-b BUFFER_COUNT]

Netflow generator for laptops

optional arguments:  
-h, --help            show this help message and exit. 
<br/>
  -i INT, --interface INT<br/>
    Monitored interface<br/>
  -s SRC_IP, --source SRC_IP<br/>
    Source IP address. Used to send packets to collector<br/>
  -sp SRC_PORT, --sport SRC_PORT<br/>
   Source port. Used to send packets to collector.Default 5000<br/>
  -d DST_IP, --destination DST_IP<br/>
    Destination IP address. Used to send packets to collector<br/>
  -dp DST_PORT, --dport DST_PORT<br/>
    Destination port. Used to send packets to collector.Default 2055<br/>
  -r SAMPLING_RATE, --rate SAMPLING_RATE<br/>
    Sampling 1 out of r packets. Default 5<br/>
  -b BUFFER_COUNT, --buffer BUFFER_COUNT<br/>
    Number of packets stored in buffer before sending them. Default 10<br/>


