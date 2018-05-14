extern crate pnet;
extern crate pcap;

use pcap::Capture;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;

use std::net::IpAddr;
use std::str;
use std::env;
use std::io::{self, Write};
use std::process;
use std::collections::HashSet;

fn main() {
  let pcap_fn = match env::args().nth(1) {
    Some(n) => n,
    None => {
      writeln!(io::stderr(), "USAGE: pcap_fun <PCAP FILENAME>").unwrap();
      process::exit(1);
    },
  };

  let mut cap = Capture::from_file(pcap_fn).unwrap();

  loop {
    match cap.next() {
      Ok(p) => {
        process_packet(p);
      }
      Err(e) => {
        break;
      }
    }
  }
}

fn process_packet(p: pcap::Packet) {
  if let Some(eth) = EthernetPacket::new(&p) {

    match eth.get_ethertype() {
      EtherTypes::Ipv4 => {
        let ip = Ipv4Packet::new(eth.payload());
        // we only care about properly parsable ipv4 packets
        if let Some(ip) = ip {
          let protocol = ip.get_next_level_protocol();
          match protocol {
            // we only care about TCP
            IpNextHeaderProtocols::Tcp => {
              let tcp = TcpPacket::new(ip.payload());
                if let Some(tcp) = tcp {
                  process_tcp_payload(tcp.payload());
                } else {
                  //println!("malformed tcp packet");
                }
            }
            _ => {
              //println!("non tcp packet");
            }
          }
        }
      },
      _ => {
        //println!("non ipv4 packet");
      }
    }
  }
}

fn process_tcp_payload(tcp_p: &[u8]) {
  if tcp_p.len() != 0 {
    let mut uniq = HashSet::new();
    for item in tcp_p.iter() {
      uniq.insert(item);
    }

    // if all of the byte values in the TCP payload data are the same
    //   (e.g. [0, 0, 0, 0, 0]) then we don't care about the packet as it
    //   is likely a protocol control packet and not a data-carrying packet
    if uniq.len() != 1 {
      determine_proto(tcp_p);
    }

  }
}

fn determine_proto(payload: &[u8]) {
  // if the first three bytes are "GET" or "POS", there's a chance the packet is HTTP
  // if the first three bytes are 0x16, 0x30, 0x00-0x03, there's a chance the packet is TLS

  let get: &[u8] = &[71, 69, 84];   // GET
  let post: &[u8] = &[80, 79, 83];  // POS
  let http: &[u8] = &[72, 84, 84];  // HTT
  let tls0: &[u8] = &[22, 3, 0];
  let tls1: &[u8] = &[22, 3, 1];
  let tls2: &[u8] = &[22, 3, 2];
  let tls3: &[u8] = &[22, 3, 3];

  let(head, tail) = payload.split_at(3);
  if head == get {
    println!("Possible HTTP GET request {:?}", payload);
  }
  if head == post {
    println!("Possible HTTP POST request {:?}", payload);
  }
  if head == http {
    println!("Possible HTTP response {:?}", payload);
  }

  if head == tls0 {
    println!("Possible SSL {:?}", payload);
  }
  if head == tls1 {
    println!("Possible TLSv1 {:?}", payload);
  }
  if head == tls2 {
    println!("Possible TLSv2 {:?}", payload);
  }
  if head == tls3 {
    println!("Possible TLSv3 {:?}", payload);
  }

}
