#!/bin/sh

IP_ADDR=$1


while [ 1 ]; do \
    python3 arp-sender.py request -i eth0 --target-ip $IP_ADDR -c 10 ; \
    python3 arp-sender.py request -i eth1 --target-ip $IP_ADDR -c 10 ; \
    python3 arp-sender.py request -i eth2 --target-ip $IP_ADDR -c 10 ; \
    python3 arp-sender.py request -i eth3 --target-ip $IP_ADDR -c 10 ; \
    python3 arp-sender.py request -i eth4 --target-ip $IP_ADDR -c 10 ; \
done