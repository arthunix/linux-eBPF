#!/bin/bash

sudo apt update
echo ----- Installing a basic C and eBPF development enviroment -----
sudo apt install build-essential ncurses-dev fakeroot wget bzip2 -y
sudo apt install llvm clang bison flex libssl-dev libelf-dev gcc-multilib -y

echo ----- Installing a bpf important packages and libraries -----
sudo apt install binutils-bpf bpfcc-tools bpftool bpftrace gcc-bpf gdb-bpf -y
sudo apt install libbpf-dev libbpfcc libbpfcc-dev -y
