use libc::{AF_INET, IPPROTO_RAW, SOCK_RAW};
use pcap::{Active, Capture, Device};
use serde::{Deserialize, Serialize};
use std::env;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::os::raw::c_void;
use std::ptr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

fn main() {
    let ip = env::args().nth(1).unwrap_or_else(|| {
        panic!("Should use: traceroute ip");
    });
    println!("Traceroute to {}", ip);
    route(&ip);
}

fn route(dest: &str) {
    let mut packet = Packet::new(dest);
    let mut old_ip = String::new();

    let socket = open_socket();
    let mut pcap = PCap::new();

    let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();

    std::thread::spawn(move || pcap.get_packet(tx));

    let mut counter = 0;

    while packet.header.ttl < 255 {
        packet.content.fill_checksum();
        let buffer = bincode::serialize(&packet).unwrap();

        send_packet(socket, dest, &buffer);

        let start = Instant::now();
        let rx_res = rx.recv_timeout(Duration::from_secs(1));
        let end = Instant::now();

        if rx_res.is_err() {
            counter += 1;
            println!("{}. * * *", counter);
            packet.header.ttl += 1;
            continue;
        }

        let data = rx_res.unwrap();
        let ip_packet: Packet = bincode::deserialize(&data[14..]).unwrap(); // skip MAC
                                                                            //println!("{:?}", ip_packet);
        if let Ok(old_packet) =
            bincode::deserialize::<Packet>(&data[14 + std::mem::size_of::<Packet>()..])
        {
            if old_packet.content != packet.content
                || packet.header.identification != old_packet.header.identification
            {
                // skip not our packets
                continue;
            }
        }

        if ip_packet.content.type_msg == 0
            && (ip_packet.content.ident != packet.content.ident
                || ip_packet.content.seq != packet.content.seq)
        {
            //
            continue;
        }

        let ip = get_ip_by_decimal(ip_packet.header.source);
        let width = 20 - ip.len();

        if old_ip == ip {
            continue;
        }

        old_ip = ip;
        counter += 1;

        println!(
            "{}. {}{:>width$}ms",
            counter,
            get_ip_by_decimal(ip_packet.header.source),
            (end - start).as_millis(),
            width = width
        );

        if ip_packet.content.type_msg == 0 {
            // icmp reply
            break;
        }

        packet.header.ttl += 1;
        packet.content.seq += 1;
    }

    close_socket(socket);
}

// rfc 792
#[allow(clippy::upper_case_acronyms)]
#[repr(packed)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq)]
struct ICMP {
    type_msg: u8,
    code: u8,
    checksum: u16,
    ident: u16,
    seq: u16,
}

// rfc 791
#[repr(packed)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
struct IpHeader {
    version_and_ihl: u8,
    type_service: u8,
    total_length: u16,
    identification: u16,
    flag_and_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source: u32,
    dest: u32,
}

#[repr(packed)]
#[derive(Serialize, Deserialize, Debug)]
struct Packet {
    header: IpHeader,
    content: ICMP,
}

struct PCap {
    cap: Capture<Active>,
}

impl PCap {
    fn new() -> Self {
        let device = Device::lookup().unwrap();
        println!("Use device: {}", device.name);
        let mut cap = Capture::from_device(device)
            .unwrap()
            .snaplen(4096)
            .timeout(1)
            .open()
            .unwrap();
        let ip = get_ip_by_decimal(get_local_ip());
        cap.filter(&format!("icmp and not src host {}", ip))
            .unwrap();
        PCap { cap }
    }

    fn get_packet(&mut self, sender: Sender<Vec<u8>>) {
        loop {
            if let Ok(packet) = self.cap.next() {
                sender.send(Vec::from(packet.data)).unwrap()
            }
        }
    }
}

impl ICMP {
    fn new() -> Self {
        let mut res = ICMP {
            type_msg: 8_u8, // ping
            code: 0,
            checksum: 0,
            ident: unsafe { libc::getpid() as u16 },
            seq: 1,
        };
        res.fill_checksum();
        res
    }
    fn fill_checksum(&mut self) {
        self.checksum = 0;
        let vec = bincode::serialize(self).unwrap();
        for word in vec.chunks(2) {
            let mut part = (word[0] as u16) << 8;
            if word.len() > 1 {
                part += word[1] as u16;
            }
            self.checksum = self.checksum.wrapping_add(part);
        }
        self.checksum = !self.checksum.to_be();
    }
}

impl IpHeader {
    fn new(dest: &str) -> Self {
        IpHeader {
            version_and_ihl: 0x45_u8, // ver=4, ihl=5
            type_service: 0,
            total_length: (std::mem::size_of::<Self>() as u16).to_be(),
            identification: 0,
            flag_and_offset: (0b0100000000000000_u16).to_be(),
            ttl: 1_u8,
            protocol: 1_u8, // icmp rfc790
            checksum: 0,    // compute after
            source: get_local_ip(),
            dest: get_ip_by_str(dest),
        }
    }
}

impl Packet {
    fn new(dest: &str) -> Self {
        Self {
            header: IpHeader::new(dest),
            content: ICMP::new(),
        }
    }
}

fn get_local_ip() -> u32 {
    unsafe {
        let mut ifaddrs = ptr::null_mut();
        let r = libc::getifaddrs(&mut ifaddrs);
        if r != 0 {
            panic!("getifaddrs return {}", r)
        }

        while !ifaddrs.is_null() {
            let addr = (*ifaddrs).ifa_addr;
            if addr.is_null() {
                ifaddrs = (*ifaddrs).ifa_next;
                continue;
            }
            match (*addr).sa_family as _ {
                libc::AF_INET => {
                    let addr = addr as *mut libc::sockaddr_in;
                    let result = (*addr).sin_addr.s_addr.to_be();
                    if result != 2130706433 {
                        // skip 127.0.0.1
                        return result.to_be();
                    } else {
                        ifaddrs = (*ifaddrs).ifa_next;
                    }
                }
                _ => {
                    ifaddrs = (*ifaddrs).ifa_next;
                    continue;
                }
            }
        }
    }
    panic!("Can't find local ipv4 address");
}

fn get_ip_by_str(ip: &str) -> u32 {
    let octets = ip.parse::<Ipv4Addr>().unwrap().octets();
    (((octets[0] as u32) << 24)
        + ((octets[1] as u32) << 16)
        + ((octets[2] as u32) << 8)
        + octets[3] as u32)
        .to_be()
}

fn get_ip_by_decimal(num: u32) -> String {
    Ipv4Addr::from(num.to_be()).to_string()
}

fn open_socket() -> i32 {
    let socket;
    unsafe {
        socket = libc::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if socket == -1 {
            panic!("Can not open socket");
        }
    }
    socket
}

fn close_socket(socket: i32) {
    unsafe {
        libc::close(socket);
    }
}

fn send_packet(socket: i32, dest: &str, buf: &[u8]) {
    unsafe {
        let result = libc::sendto(
            socket,
            buf.as_ptr() as *const c_void,
            buf.len() as libc::size_t,
            0,
            &to_sock_addr(dest) as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
        );
        if result < 0 {
            panic!("Can not send packet");
        }
    }
}

fn to_sock_addr(dest: &str) -> libc::sockaddr {
    let addr_str = dest.to_owned() + ":0";
    let address = addr_str.to_socket_addrs().unwrap().next().unwrap();
    match address {
        SocketAddr::V4(v4) => {
            unsafe {
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                sa.sin_family = 2; // AF_INET
                sa.sin_port = v4.port().to_be();
                sa.sin_addr = *(&v4.ip().octets() as *const u8 as *const libc::in_addr);
                *(&sa as *const libc::sockaddr_in as *const libc::sockaddr)
            }
        }
        SocketAddr::V6(_) => {
            panic!("IpV6 is not supported");
        }
    }
}
