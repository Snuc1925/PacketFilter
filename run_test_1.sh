# for i in {1..10000}; do 
  sudo ip netns exec victim-ns curl -o /dev/null -s -w \
"namelookup: %{time_namelookup}\nconnect: %{time_connect}\nappconnect: %{time_appconnect}\npretransfer: %{time_pretransfer}\nstarttransfer: %{time_starttransfer}\ntotal: %{time_total}\n" \
http://192.168.100.1/ | awk -F': ' '{printf "%s: %.0f ms\n",$1,$2*1000}'
# done | awk '{sum+=$1} END {print "avg latency:",sum/NR,"s"}'
