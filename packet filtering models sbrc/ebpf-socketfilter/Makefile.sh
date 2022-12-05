#!/usr/bin/env sh

if [[ "$1" = "clean" ]]; then
    rm -rf sockfilter
    cd ../../libbpf-bootstrap/examples/c
    make clean
    exit
fi

cd ../../libbpf-bootstrap/examples/c
make
cd ../../../packet\ filtering\ models\ sbrc/ebpf-socketfilter/
ln -s ../../libbpf-bootstrap/examples/c/sockfilter