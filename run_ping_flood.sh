#!/bin/sh


. ./ip_list.sh


start_ping_flood()
{
    addr=$1
    iface=$2
    size=$3

    echo "Pinging $addr from $if with size $size"

    ping -f -s $size -I $iface $addr &

}

IF=$1
SIZE=$2



#while [ 1 ]; do
    for target in $ip_list; do
        start_ping_flood $target $IF $SIZE
    done
#done

