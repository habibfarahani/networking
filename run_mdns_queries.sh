
. ./if_list.sh

while [ 1 ]; do

    for if in $iflist; do
        echo "IF: [$if]"
        python3 standalone/mdns_if_query.py $if _services._dns-sd._udp.local   --qtype TXT --timeout 10
        python3 standalone/mdns_if_query.py $if _services._dns-sd._udp.local   --qtype PTR --timeout 10
        python3 standalone/mdns_if_query.py $if _services._dns-sd._udp.local   --qtype AAAA --timeout 10
        python3 standalone/mdns_if_query.py $if _http._tcp.local --qtype TXT --timeout 10
        python3 standalone/mdns_if_query.py $if _http._tcp.local --qtype PTR --timeout 10
        python3 standalone/mdns_if_query.py $if _http._tcp.local --qtype AAAA --timeout 10

    done
done