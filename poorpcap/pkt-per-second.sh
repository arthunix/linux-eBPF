#!/bin/bash

INTERVAL="1"  # update interval in seconds

if [ -z "$1" ]; then
        echo
        echo usage: $0 [network interface] [interval]
        echo
        exit
fi

if [ "$2" ]; then
        INTERVAL=$2
fi

IF=$1

echo "Measuring at interface: $1 - Starting at time: $(date)"
while true
do
        rxp1=`cat /sys/class/net/$1/statistics/rx_packets`
        txp1=`cat /sys/class/net/$1/statistics/tx_packets`
        rxb1=`cat /sys/class/net/$1/statistics/rx_bytes`
        txb1=`cat /sys/class/net/$1/statistics/tx_bytes`
        rxd1=`cat /sys/class/net/$1/statistics/rx_dropped`
        txd1=`cat /sys/class/net/$1/statistics/tx_dropped`
        sleep $INTERVAL
        rxp2=`cat /sys/class/net/$1/statistics/rx_packets`
        txp2=`cat /sys/class/net/$1/statistics/tx_packets`
        rxb2=`cat /sys/class/net/$1/statistics/rx_bytes`
        txb2=`cat /sys/class/net/$1/statistics/tx_bytes`
        rxd2=`cat /sys/class/net/$1/statistics/rx_dropped`
        txd2=`cat /sys/class/net/$1/statistics/tx_dropped`
        
        rxppersecond=`expr $rxp2 - $rxp1`
        txppersecond=`expr $txp2 - $txp1`
        rxbpersecond=`expr $rxb2 - $rxb1`
        txbpersecond=`expr $txb2 - $txb1`
        rxdpersecond=`expr $rxd2 - $rxd1`
        txdpersecond=`expr $txd2 - $txd1`
        
        echo "rx_packets: $rxppersecond pkts/s | tx_packets: $txppersecond pkts/s | rx_bytes: $rxbpersecond bytes/s | tx_bytes: $txbpersecond bytes/s | rx_dropped: $rxdpersecond pkts/s | tx_dropped: $txdpersecond pkts/s"
done
echo "Measuring at interface: $1 - Stopping at time: $(date)"
