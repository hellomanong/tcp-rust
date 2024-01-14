use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::Ipv4Addr,
};

use etherparse::Ipv4HeaderSlice;
use tcp::Connection;
use tun_tap::{Iface, Mode};

mod tcp;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, Connection> = Default::default();

    // mode==tun 表示网络层数据，前置4字节数据，前两个字节是flags，后两个字节是协议，ipv4，ivp6
    let mut iface =
        Iface::without_packet_info("mytun", Mode::Tun).expect("Failed to create a TUN device");
    let mut buf = vec![0; 1504]; // MTU + 4 for the header

    loop {
        let nbytes = iface.recv(&mut buf)?;
        // 解析前置的4字节数据，首部中的字段均以大端序包装
        // let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let proto = u16::from_be_bytes([buf[2], buf[3]]);
        // // 查看协议号：https://en.wikipedia.org/wiki/EtherType
        // if proto != 0x0800 {
        //     // 不是ipv4
        //     continue;
        // }

        match Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                // tcp=0x06 : 查看ip协议号列表：https://zh.wikipedia.org/wiki/IP%E5%8D%8F%E8%AE%AE%E5%8F%B7%E5%88%97%E8%A1%A8
                let proto = iph.protocol();
                if proto != 0x06 {
                    // 不是tcp
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        // 从数据包的开头到tcp头结束
                        let datai = iph.slice().len() + tcph.slice().len();
                        match connections.entry(Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        }) {
                            Entry::Occupied(mut v) => {
                                v.get_mut().on_packet(
                                    &mut iface,
                                    iph,
                                    tcph,
                                    &buf[datai..nbytes],
                                )?;
                            }
                            Entry::Vacant(v) => {
                                if let Some(c) =
                                    Connection::accept(&mut iface, iph, tcph, &buf[datai..nbytes])?
                                {
                                    v.insert(c);
                                }
                            }
                        }
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
