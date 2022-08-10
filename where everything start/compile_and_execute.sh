if [[ "$1" = "unload" ]]; then
    read -p "Please put the name of the device: " devname
    sudo ip link set dev $devname xdp off
    exit
fi

echo Compiling source code to bpf bytecode
clang -target bpf -O2 -c xdp_drop.c -o xdp_drop.o
if [ $? -ne 0 ]; then
    exit
fi
echo sucess!!!

ifconfig
read -p "Please put the name of the device: " devname
sudo ip -force link set dev $devname xdp obj xdp_drop.o sec .text
ip link show dev $devname
