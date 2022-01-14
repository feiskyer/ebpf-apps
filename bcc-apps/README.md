# eBPF apps based on BCC (BPF Compiler Collection).

## Contents

## Contents

* [c](c): BCC apps with C bindings.
* [cpp](cpp): BCC apps with cpp bindings.
* [python](python): BCC apps with Python bindings.

## Pre-requisites

[BCC](https://github.com/iovisor/bcc) and its development libraries should be installed.

### Install from packages

Please follow [INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md) to see the detailed guides. For example, on Ubuntu or RHEL:

```sh
# Ubuntu
sudo apt-get install bpfcc-tools libbpfcc-dev linux-headers-$(uname -r)

# RHEL
sudo yum install bcc-tools bcc-devel
```

### Install from source

Please follow [INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md#source) to see the detailed guides. For example, on Ubuntu 20.04+:

```sh
sudo apt install -y bison build-essential cmake flex git libedit-dev llvm-dev libclang-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils

git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```
