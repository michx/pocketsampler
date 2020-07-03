# Pocketsampler

This is a simple Flow Generator. It captures traffic from desired interface and creates flow samples to be sent to a desired collector.
It uses scapy and libpcap libraries.


## Before installing

The script requires libpcap source libraries:

sudo apt install libpcap-dev


## Installation

pip install -r requirements.txt


## Usage

You can find help inline, as below.

usage: scratch.py [-h] [-i INT] [-s SRC_IP] [-sp SRC_PORT] [-d DST_IP]
                  [-dp DST_PORT] [-r SAMPLING_RATE] [-b BUFFER_COUNT]

Netflow generator for laptops

optional arguments:
  -h, --help            show this help message and exit

  -i INT, --interface INT
    Monitored interface
  -s SRC_IP, --source SRC_IP
    Source IP address. Used to send packets to collector
  -sp SRC_PORT, --sport SRC_PORT
   Source port. Used to send packets to collector.Default 5000
  -d DST_IP, --destination DST_IP
    Destination IP address. Used to send packets to collector
  -dp DST_PORT, --dport DST_PORT
    Destination port. Used to send packets to collector.Default 2055
  -r SAMPLING_RATE, --rate SAMPLING_RATE
    Sampling 1 out of r packets. Default 5
  -b BUFFER_COUNT, --buffer BUFFER_COUNT
    Number of packets stored in buffer before sending them. Default 10


