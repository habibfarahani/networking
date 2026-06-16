#!/bin/sh

. ./ip_list.sh
. ./if_list.sh


while [ 1 ]; do
    for target in $ip_list; do
        for if in $iflist; do
            echo "ARPing: [$if] [$target]"
            python3 standalone/arp-sender.py request -i "$if" --target-ip "$target" -c 10
        done 
    done
done
