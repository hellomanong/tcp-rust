#!/bin/bash
cargo build

#编译报错直接退出
ext=$?
if [[ $ext -ne 0 ]]; then
        exit $ext
fi

#设置权限
sudo setcap cap_net_admin=eip $HOME/rust/tcp-rust/target/debug/tcp-rust

#程序后台运行
$HOME/rust/tcp-rust/target/debug/tcp-rust &

#获取最后一个后台运行的pid
pid=$!

sudo  ip addr add 192.168.0.1/24 dev mytun
sudo ip link set up dev mytun

#ctrl+c 退出程序
trap "kill $pid" INT TERM

wait $pid