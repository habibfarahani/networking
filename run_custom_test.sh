#!/bin/sh

ip_list="
    192.168.168.101 
    192.168.168.100 
    192.168.168.135 
    192.168.168.106
    192.168.168.121
    192.168.168.117
    192.168.168.154
    192.168.168.158
    192.168.168.112
    192.168.168.51
    192.168.168.52
    192.168.168.53
    192.168.168.54
    192.168.168.41
    192.168.168.42
    192.168.168.43
    192.168.168.44
    192.168.168.31
    192.168.168.32
    192.168.168.33
    192.168.168.34
    192.168.168.21
    192.168.168.22
    192.168.168.23
    192.168.168.24
    192.168.168.11
    192.168.168.12
    192.168.168.13
    192.168.168.14
"


IF=$1

start_ping_flood()
{
    addr=$1
    iface=$2
    size=$3
    count=$4

    ping -f -w 1 -c $count -s $size -I $iface $addr 

}

while [ 1 ] do

    for target in $ip_list; do
        echo "Deploying to: [$target]"
        python3 standalone/arp-sender.py request -i "$IF" --target-ip "$target" -c 10
        start_ping_flood "$target" "$IF" "3333"  "100"
        python3 standalone/mdns_if_query.py $IF _services._dns-sd._udp.local   --qtype TXT --timeout 10
        python3 standalone/mdns_if_query.py $IF _services._dns-sd._udp.local   --qtype PTR --timeout 10
        python3 standalone/mdns_if_query.py $IF _services._dns-sd._udp.local   --qtype AAAA --timeout 10

    done 

done
# start_ping_flood "192.168.168.101" $IF 3333 50
# start_ping_flood "192.168.168.151" $IF 3333 50
# start_ping_flood "192.168.168.101" $IF 3333 50
# start_ping_flood "192.168.168.101" $IF 3333 50
# start_ping_flood "192.168.168.101" $IF 3333 50
