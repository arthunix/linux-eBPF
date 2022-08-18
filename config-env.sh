#!/bin/bash

echo Installing a basic C and eBPF development enviroment
sudo dnf group install "C Development Tools and Libraries" "Development Tools" -y
sudo dnf install emacs clang llvm elfutils-libelf-devel -y
sudo dnf install flex bison python3 minicom ncurses-devel make automake gcc gcc-c++ kernel-devel -y
sudo dnf install qemu-system-x86 qemu-system-arm -y
sudo dnf install kernel-devel kernel-headers kernel-doc -y

echo Installing a bpf important packages and libraries
sudo dnf install bcc bcc-devel bcc-tools libbpf libbpf-devel libbpf-tools -y
sudo dnf install bpfmon bpftool bpftrace -y
