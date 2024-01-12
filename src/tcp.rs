use std::{default, io};

use tun_tap::Iface;

#[derive(Debug)]
pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Esta,
}

#[derive(Default)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

/// State Of Send Sequence Space (RFC 793 s3.2 F5)  发送序列空间
///
///             1         2          3          4
///         ----------|----------|----------|----------
///                 SND.UNA    SND.NXT    SND.UNA
///                                     +SND.WND

/// 1 - old sequence numbers which have been acknowledged  // 已确认的旧序列号
/// 2 - sequence numbers of unacknowledged data            // 未确认数据的序列号
/// 3 - sequence numbers allowed for new data transmission // 允许新数据传输的序列号
/// 4 - future sequence numbers which are not yet allowed  // 尚未允许的未来序列号

#[derive(Default)]
struct SendSequenceSpace {
    una: u32,   // send unacknowledged 发送未确认
    nxt: u32,   // send next 发送下一个
    wnd: u16,   // send window 发送窗口
    up: bool,   // send urgent pointer 发送紧急指针
    wl1: usize, // segment sequence number used for last window updat 用于上次窗口更新的段序列号
    wl2: usize, // segment acknowledgment number used for last window 用于上次窗口更新的段确认号
    iss: u32,   // initial send sequence number 初始发送序列号
}

///Receive Sequence Space (RFC 793 s3.2 F5) 接收序列空间
///
///                 1          2          3      
///             ----------|----------|----------
///                     RCV.NXT    RCV.NXT        
///                             +RCV.WND        
/// 1 - old sequence numbers which have been acknowledged  // 已确认的旧序列号
/// 2 - sequence numbers allowed for new reception         // 允许新接收的序列号
/// 3 - future sequence numbers which are not yet allowed  // 尚未允许的未来序列号

#[derive(Default)]
struct RecvSequenceSpace {
    nxt: u32, // RCV.NXT - receive next
    wnd: u16, // RCV.WND - receive window
    up: bool, // RCV.UP  - receive urgent pointer
    irs: u32, // IRS     - initial receive sequence number
}

impl Default for State {
    fn default() -> Self {
        State::Listen
    }
}

impl Connection {
    pub fn on_packet(
        &mut self,
        iface: &mut Iface,
        iph: etherparse::Ipv4HeaderSlice,
        tcph: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        match self.state {
            State::Closed => {
                return Ok(0);
            }
            State::Listen => {
                if !tcph.syn() {
                    // 只希望获得 SYN packet
                    return Ok(0);
                }

                // keep track of sender info
                self.recv.nxt = tcph.sequence_number() + 1;
                self.recv.wnd = tcph.window_size();
                self.recv.irs = tcph.sequence_number();

                // decide on stuff we're sending them
                self.send.iss = 0;
                self.send.una = self.send.iss;
                self.send.nxt = self.send.una + 1;
                self.send.wnd = 10;

                // need to start establishing a connection
                // 先拼装tcp的包头
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcph.destination_port(), // 源端口
                    tcph.source_port(),      // 目的端口
                    self.send.iss,           // 序列号应该是随机的，0 ~ 2**32-1
                    self.send.wnd,           // 数据窗口大小
                );
                syn_ack.syn = true; // 发给客户端的 syn
                syn_ack.ack = true; // 发给客户端的 ack
                syn_ack.acknowledgment_number = self.recv.nxt;

                // 拼装ip包头
                let mut ip = etherparse::Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    etherparse::IpNumber::Tcp as _,
                    iph.destination(),
                    iph.source(),
                );

                // 检验和
                syn_ack.checksum = syn_ack
                    .calc_checksum_ipv4(&ip, &[])
                    .expect("failed to compute checksum");

                // write out the headers
                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    let _ = ip.write(&mut unwritten);
                    let _ = syn_ack.write(&mut unwritten);
                    unwritten.len()
                };

                iface.send(&buf[..buf.len() - unwritten])?;
            }
            _ => {}
        }

        println!(
            "{}:{} -> {}:{} {}b of tcp",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len(),
        );

        Ok(0)
    }
}
