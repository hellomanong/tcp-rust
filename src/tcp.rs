use std::cmp::{min, Ordering::*};
use std::io::{self, Write};
use std::usize::MIN;
use tun_tap::Iface;

#[derive(Debug)]
pub enum State {
    SynRcvd,
    Estab,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab => true,
        }
    }
}

#[derive(Default)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
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
        State::SynRcvd
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

        conn.tcp = syn_ack;

        conn.write(iface, &[])?;

        Ok(Some(conn))
    }

    pub fn send_rst(&mut self, iface: &mut Iface) -> io::Result<()> {
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.ip.set_payload_len(self.tcp.header_len() as _);
        self.write(iface, &[])?;
        Ok(())
    }

    pub fn write(&mut self, iface: &mut Iface, payload: &[u8]) -> io::Result<usize> {
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;
        self.ip
            .set_payload_len(self.tcp.header_len() as usize + payload.len());

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        let mut buf = [0u8; 1500];
        // let size = min(
        //     buf.len(),
        //     self.ip.header_len() + self.tcp.header_len() as usize + payload.len(),
        // );

        let mut unwritten = buf.as_mut_slice();
        let _ = self.ip.write(&mut unwritten);
        let _ = self.tcp.write(&mut unwritten);
        let payload_bytes = unwritten.write(payload)?;

        let unwritten = unwritten.len(); // 剩余的空间
        iface.send(&buf[..buf.len() - unwritten])?;

        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);

        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }

        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        Ok(payload_bytes)
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
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            return Ok(());
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
        // |--S--------|-----------------------------------------------|------>|

        let seqn = tcph.sequence_number();

        // or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as _);
        let mut slen = data.len() as u32;

        // 只有SYN和FIN，即使有效载荷为零，也会占用一个序列号号，必须设置SEG.LEN = 1
        // SEG.LEN 是有效载荷长度，也就是tcp段除去，header后的数据长度
        if tcph.syn() || tcph.fin() {
            slen += 1;
        }

        if data.len() == 0 {
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(self.recv.nxt, seqn.wrapping_add(slen - 1), wend)
            {
                return Ok(());
            }
        }

        match self.state {
            State::SynRcvd => {
                if !tcph.ack() {
                    return Ok(());
                }
            }
            State::Estab => {}
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

// 改成统一的 start < x < end
// 省略 = 的判断， 在调用处，+1或者 -1 来处理
fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    match start.cmp(&x) {
        Equal => return false,
        Less => {
            // start < x 的情况下，end在中间是错误的，在两头没事
            if end >= start && end <= x {
                return false;
            };
        }
        Greater => {
            // end在中间没事  x < end < start
            if end > x && end < start {
            } else {
                return false;
            };
        }
    }

    true
}
