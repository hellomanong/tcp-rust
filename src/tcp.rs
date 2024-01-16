use std::cmp::Ordering::*;
use std::io;
use std::ops::Add;

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
    ip: etherparse::Ipv4Header,
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
    wnd: u32,   // send window 发送窗口
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
    pub fn accept(
        iface: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice,
        tcph: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<Option<Self>> {
        if !tcph.syn() {
            // 只希望获得 SYN packet
            return Ok(None);
        }

        let mut conn = Connection::default();
        conn.state = State::SynRcvd;

        // keep track of sender info
        conn.recv.nxt = tcph.sequence_number() + 1;
        conn.recv.wnd = tcph.window_size();
        conn.recv.irs = tcph.sequence_number();

        // decide on stuff we're sending them
        conn.send.iss = 0;
        conn.send.una = conn.send.iss;
        conn.send.nxt = conn.send.una + 1;
        conn.send.wnd = 10;

        // need to start establishing a connection
        // 先拼装tcp的包头
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(), // 源端口
            tcph.source_port(),      // 目的端口
            conn.send.iss,           // 序列号应该是随机的，0 ~ 2**32-1
            conn.send.wnd as _,      // 数据窗口大小
        );
        syn_ack.syn = true; // 发给客户端的 syn
        syn_ack.ack = true; // 发给客户端的 ack
        syn_ack.acknowledgment_number = conn.recv.nxt;
        // 拼装ip包头
        conn.ip = etherparse::Ipv4Header::new(
            syn_ack.header_len(),
            64,
            etherparse::IpNumber::Tcp as _,
            iph.destination(),
            iph.source(),
        );

        conn.ip.set_payload_len(syn_ack.header_len() as _);

        // 检验和
        syn_ack.checksum = syn_ack
            .calc_checksum_ipv4(&conn.ip, &[])
            .expect("failed to compute checksum");

        let mut buf = [0u8; 1500];
        // write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            let _ = conn.ip.write(&mut unwritten);
            let _ = syn_ack.write(&mut unwritten);
            unwritten.len()
        };

        iface.send(&buf[..buf.len() - unwritten])?;

        Ok(Some(conn))
    }

    pub fn on_packet(
        &mut self,
        iface: &mut Iface,
        iph: etherparse::Ipv4HeaderSlice,
        tcph: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<()> {
        // 段变量SEG：Tcp段是 TCP/IP 网络通信中的基本数据单元，它包含了控制信息和用户数据。这些信息被封装在 TCP 头部和数据部分
        //           本质上是tcp两端维护的逻辑变量，在发送一段tcp数据包的时候，会把SEG的数据，包进Tcp数据中；
        //           窗口中就是一个一个段；
        // 发送序列变量SND：是 TCP 连接中用于跟踪和管理发送方状态的一组变量

        // SND.UNA < SEG.ACK =< SND.NXT
        // A - B （我是A）
        // SND.UNA: A 已发送的数据中最早的那个尚未被 B 确认的字节
        // SEG.ACK: B 给A 的确认，希望下次A 发送的序列号；代表的是接收方希望下次发送方的SEQ;
        // SND.NXT: A 计划发送的下一个数据字节的序列号

        // 正常的情况1
        // 0                                                                    0
        // |----------------------------U--A--N-------------------------------->|
        // 正常情况2
        // 0                                                                    0
        // |--A--N----------------------------------------------------------U-->|
        // 0                                                                    0
        // |--N----------------------------------------------------------U--A-->|

        let ackn = tcph.acknowledgment_number();

        match self.send.una.cmp(&ackn) {
            Equal => return Ok(()),
            Less => {
                // U<A 的情況下，N在中间是错的，在两头没事
                if self.send.nxt >= self.send.una && self.send.nxt < ackn {
                    return Ok(());
                }
            }
            Greater => {
                // N在中间没事
                if self.send.nxt >= ackn && self.send.nxt < self.send.una {
                } else {
                    return Ok(());
                }
            }
        }

        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND , RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        // A - B (我是A)
        // RCV.NXT: 接收端（A）期望接收的下一个字节的序列号,它表示 A 已成功接收到的数据的序列号加一
        // SEG.SEQ：这是收到的 TCP 段（从 B 发送给 A）的起始序列号。它标识段中第一个字节的序列号
        // RCV.WND: 这是接收端（A）的接收窗口大小，表示 A 能够接收的、从 RCV.NXT 开始的字节数
        // SEG.SEQ < RCV.NXT+RCV.WND: 如果 SEG.SEQ 大于或等于窗口结束位置，那么该段完全位于接收端的接收窗口之外，意味着接收端目前没有足够的空间或还未准备好接收这部分数据。

        // N: NXT, S: SEQ, W: NXT+WND
        // 正常的情况1
        // 0                   N                                    W          0
        // |-------------------|------------S-----------------------|--------->|
        // 正常情况2, 序列号回环了
        // 0-----------W                                               N-------0
        // |-----------|-----------------------------------------------|---S-->|
        // 0-----------W                                               N-------0
        // |--S--------|------------------------------------------ ----|------>|

        let seqn = tcph.sequence_number();
        match self.send.nxt.cmp(&seqn) {
            Equal => {}
            Less => {
                // N<S 的情况下，W在中间是错误的，在两头没事
                if self.send.nxt.wrapping_add(self.send.wnd) >= self.send.nxt
                    && self.send.nxt.wrapping_add(self.send.wnd) <= seqn
                {
                    return Ok(());
                }
            }
            Greater => {
                // W在中间没事
                if self.send.nxt.wrapping_add(self.send.wnd) > seqn
                    && self.send.nxt.wrapping_add(self.send.wnd) < self.send.nxt
                {
                } else {
                    return Ok(());
                }
            }
        }

        match self.state {
            State::Closed => {
                return Ok(());
            }
            State::Listen => {}
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

        Ok(())
    }
}
