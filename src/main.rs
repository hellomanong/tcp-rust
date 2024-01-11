use std::io;

use etherparse::Ipv4HeaderSlice;
use tun_tap::{Iface, Mode};

fn main() -> io::Result<()> {
    // mode==tun 表示网络层数据，前置4字节数据，前两个字节是flags，后两个字节是协议，ipv4，ivp6
    let iface = Iface::new("mytun", Mode::Tun).expect("Failed to create a TUN device");
    // Configure the device ‒ set IP address on it, bring it up.
    let mut buf = vec![0; 1504]; // MTU + 4 for the header

    loop {
        let nbytes = iface.recv(&mut buf)?;
        // 解析前置的4字节数据，首部中的字段均以大端序包装
        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        // 查看协议号：https://en.wikipedia.org/wiki/EtherType
        if proto != 0x0800 {
            // 不是ipv4
            continue;
        }

        match Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                // tcp=0x06 : 查看ip协议号列表：https://zh.wikipedia.org/wiki/IP%E5%8D%8F%E8%AE%AE%E5%8F%B7%E5%88%97%E8%A1%A8
                let proto = iph.protocol();
                if proto != 0x06 {
                    // 不是tcp
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        println!(
                            "{} -> {} {}b of tcp to port {}",
                            src,
                            dst,
                            tcph.slice().len(),
                            tcph.destination_port(),
                        );
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring weird packet {:?}", e);
            }
        }
    }
}
