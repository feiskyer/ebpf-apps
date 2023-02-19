# Dropping packets with TC

This is a simple example of how to use the Traffic Control (TC) tool to drop packets.

## Prerequisites

```sh
cargo install libbpf-cargo
```

## Build

```sh
cargo libbpf make
```

## Load

```sh
./target/debug/tc_block_tcp --interface eth0 --attach
```

## Unload

```sh
./target/debug/tc_block_tcp --interface eth0 --detach
```
