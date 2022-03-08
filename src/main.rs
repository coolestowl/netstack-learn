extern crate tun_tap;

use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::fmt;
use std::time::Duration;

use tun_tap::{Iface, Mode};

const PING: &[u8] = &[0, 0, 8, 0, 69, 0, 0, 84, 44, 166, 64, 0, 64, 1, 247, 40, 10, 107, 1, 2, 10,
    107, 1, 3, 8, 0, 62, 248, 19, 160, 0, 2, 232, 228, 34, 90, 0, 0, 0, 0, 216, 83, 3, 0, 0, 0, 0,
    0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55];

fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new(cmd)
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execute {}", cmd);
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct MACAddr([u8; 6]);

impl fmt::Display for MACAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = self.0.iter().map(|b| {
            format!("{:X}", b)
        }).collect::<Vec<_>>().join(":");
        
        write!(f, "MACAddr({})", str)
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct IPv4Addr([u8; 4]);

impl fmt::Display for IPv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IPv4Addr({})", std::net::Ipv4Addr::new(self.0[0], self.0[1], self.0[2], self.0[3]))
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Op([u8; 2]);

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Op({})", match self.0 {
            [0x00, 0x01] => "ReqARP".into(),
            [0x00, 0x02] => "RespARP".into(),
            [0x00, 0x03] => "ReqRARP".into(),
            [0x00, 0x04] => "RespRARP".into(),
            _ => format!("{:?}", self.0),
        })
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct ARPHeader {
    hw_type: [u8; 2], // hardware type
    pt_type: [u8; 2], // protocal type
    hw_length: u8,    // hardware size
    pt_length: u8,    // protocal size
    op_code: Op,      // operation, 1 for ARP req, 2 for ARP resp, 3 for RARP req, 4 for RARP resp
    smac: MACAddr,    // source MAC addr
    sip: IPv4Addr,    // source IP addr
    dmac: MACAddr,    // destination MAC addr
    dip: IPv4Addr,    // destination IP addr
}

impl fmt::Display for ARPHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {}) === {} ==> ({}, {})",
            self.sip, self.smac,
            self.op_code,
            self.dip, self.dmac,
        )
    }
}

impl<T> From<T> for ARPHeader
where
    T: AsRef<[u8]>
{
    fn from(data: T) -> ARPHeader {
        let v = data.as_ref();
        assert!(v.len() >= 28, "not enough data");

        unsafe { u8_slice_as_any(v) }
    }
}

unsafe fn u8_slice_as_any<T: Sized>(p: &[u8]) -> &T {
    let (head, body, _tail) = p.align_to::<T>();
    assert!(head.is_empty(), "aligh failed");
    body[0]
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}

#[derive(Debug)]
enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Others,
}

impl EtherType {
    fn from(t: u16) -> Self {
        match t {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::ARP,
            0x86DD => EtherType::IPv6,
            _ => EtherType::Others,
        }
    }
}

fn main() {
    let iface = Iface::new("testtap%d", Mode::Tap).unwrap();
    //let iface = Iface::new("testtun%d", Mode::Tun).unwrap();

    cmd("ip", &["addr", "add", "dev", iface.name(), "10.107.1.2/24"]);
    cmd("ip", &["link", "set", "up", "dev", iface.name()]);

    let iface = Arc::new(iface);
    let iface_writer = Arc::clone(&iface);
    let iface_reader = Arc::clone(&iface);

    /*
    let writer = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));
            println!("Sending a ping");
            let amount = iface_writer.send(PING).unwrap();
            assert!(amount == PING.len());
        }
    });*/

    let reader = thread::spawn(move || {
        let mut buffer = vec![0; 1504];

        loop {
            let size = iface_reader.recv(&mut buffer).unwrap();
            assert!(size >= 4);

            let t = EtherType::from(u8_as_u16(&buffer[2..4]));
            if let EtherType::IPv6 = t {
                println!("ignore v6");
            } else {
                println!("{:?}: {:?}", t, &buffer[0..size]);
            }

            if let EtherType::ARP = t {
                assert!(size >= 46);
                
                let ip_last: u8 = buffer[45];

                for i in 4..10 { // swap ether layer mac addr
                    buffer.swap(i, i+6);
                }
                for i in 32..36 { // swap ip layer ip addr
                    buffer.swap(i, i+10);
                }
                for i in 26..32 { // swap ip layer mac addr
                    buffer.swap(i, i+10);
                }

                for i in 26..32 {
                    buffer[i] = ip_last;
                }

                let resp: &[u8] = &buffer[0..size];
                let amount = iface_writer.send(resp).unwrap();
                assert!(amount == resp.len());

                println!("Sent: {:?}", resp);
            }
        }
    });

    // writer.join().unwrap();
    reader.join().unwrap();
}

fn u8_as_u16(vec: &[u8]) -> u16 {
    assert!(vec.len() >= 2);

    ((vec[0] as u16) << 8) | vec[1] as u16
}
