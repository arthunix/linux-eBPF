#!/bin/sh

sudo dnf update --refresh

sudo dnf group install "C Development Tools and Libraries" "Development Tools" -y
sudo dnf install emacs clang llvm elfutils-libelf-devel elfutils-libelf glibc-devel -y
sudo dnf install kernel-tools kernel-tools-libs kernel-tools-libs-devel kernel-core kernel-modules -y
sudo dnf install binutils-devel binutils flex flex-devel bison bison-devel ncurses ncurses-devel ncurses-libs -y
sudo dnf install flex bison python3 minicom ncurses-devel make automake gcc gcc-c++ kernel-devel -y
sudo dnf install qemu-system-x86 qemu-system-arm kernel-devel kernel-headers kernel-doc -y
sudo dnf install bcc bcc-devel bcc-tools libbpf libbpf-devel libbpf-tools -y
sudo dnf install bpfmon bpftool bpftrace libpcap libpcap-devel -y
