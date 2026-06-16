#!/bin/sh



start_ping_flood()
{
    addr=$1
    iface=$2
    size=$3

    ping -f -s $size -I $iface $addr 

}



start_ping_flood "192.168.168.101" "eth0" 3333

