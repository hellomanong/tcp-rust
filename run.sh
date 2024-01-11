#!/bin/bash
cargo build
sudo setcap cap_net_admin=eip $HOME/rust/tcp-rust/target/debug/tcp-rust
$HOME/rust/tcp-rust/target/debug/tcp-rust &
pid=$!
sudo  ip addr add 192.168.0.1/24 dev mytun
sudo ip link set up dev mytun
trap "kill $pid" INT TERM
wait $pid