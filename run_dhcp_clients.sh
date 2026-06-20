#!/bin/sh

IF=$1

. ./mac_list.sh


while [ 1 ]
do
    for mac in $mac_list 
    do
    #    echo "MAC: [$mac]"
        python3 ./standalone/dhcp4_client.py -i $IF --mac $mac
    done
done
