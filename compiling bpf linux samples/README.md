# How to compile eBPF /linux/samples/bpf

## Download source code:
```sh
git clone git@github.com:torvalds/linux.git
```
```sh
# Make sure the options are in .config
CONFIG_BPF=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
CONFIG_KPROBES=y
CONFIG_HAVE_KPROBES=y
CONFIG_CGROUPS=y
CONFIG_USERMODE_DRIVER=y
CONFIG_BPF_PRELOAD=y
CONFIG_BPF_LSM=y
```
```sh
make -C tools clean
make -C samples/bpf clean
make clean
make defconfig
make headers_install
bpftool btf dump file /sys/kernel/btf/vmlinux format c > samples/bpf/vmlinux.h
make M=samples/bpf
```