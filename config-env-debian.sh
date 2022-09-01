#!/bin/bash

sudo apt update
sudo apt install build-essential ncurses-dev fakeroot wget bzip2
sudo apt install llvm clang bison flex libssl-dev libelf-dev
sudo apt install binutils-bpf bpfcc-tools bpftool bpftrace gcc-bpf gdb-bpf
sudo apt install libbpf-dev libbpfcc libbpfcc-dev gcc-multilib
