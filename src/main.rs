use clap::Parser;
use core::net::{Ipv4Addr, Ipv6Addr};
use pcap_file::pcap::{PcapPacket, PcapReader, PcapWriter};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::fs::File;

#[derive(Parser, Debug)]
#[command(version, about = "Simple program for reading input .pcap-file (.pcapng is not supported yet), incrementing selected MAC/IPv4/IPv6 octets and writing changed data to output file. Broadcast/Multicast/Zero-addresses is not incremented.", long_about = None)]
struct Args {
    #[arg(long)]
    in_file: String,

    #[arg(long)]
    out_file: String,

    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=5))]
    /// MAC-address octet number for incrementing. Numbering starts from 0)
    mac_octet_number: u8,

    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=3))]
    /// IPv4-address octet number for incrementing. Numbering starts from 0)
    ipv4_octet_number: u8,

    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=15))]
    /// IPv6-address octet number for incrementing. Numbering starts from 0)
    ipv6_octet_number: u8,
}

trait OctetIncrement {
    fn octet_increment(&mut self, octet_number: u8);
}

impl OctetIncrement for MacAddr {
    fn octet_increment(&mut self, octet_number: u8) {
        match octet_number {
            0 => self.0 = self.0.wrapping_add(1),
            1 => self.1 = self.1.wrapping_add(1),
            2 => self.2 = self.2.wrapping_add(1),
            3 => self.3 = self.3.wrapping_add(1),
            4 => self.4 = self.4.wrapping_add(1),
            5 => self.5 = self.5.wrapping_add(1),
            _ => panic!(),
        }
    }
}

impl OctetIncrement for Ipv4Addr {
    fn octet_increment(&mut self, octet_number: u8) {
        let mut octets = self.octets();
        octets[octet_number as usize] = octets[octet_number as usize].wrapping_add(1);
        *self = Ipv4Addr::from_octets(octets);
    }
}

impl OctetIncrement for Ipv6Addr {
    fn octet_increment(&mut self, octet_number: u8) {
        let mut octets = self.octets();
        octets[octet_number as usize] = octets[octet_number as usize].wrapping_add(1);
        *self = Ipv6Addr::from_octets(octets);
    }
}

fn main() {
    let args = Args::parse();
    let file_in = File::open(args.in_file).expect("Error opening file");
    let file_out = File::create(args.out_file).expect("Error creating file");
    let mut pcap_reader = PcapReader::new(file_in).unwrap();
    let mut pcap_writer = PcapWriter::new(file_out).unwrap();
    let mut packet_number = 0u128;
    // Read test.pcap
    while let Some(pkt) = pcap_reader.next_packet() {
        if let Ok(pkt) = pkt {
            packet_number += 1;
            let mut data: Vec<u8> = pkt.data.clone().into();

            if let Some(mut eth_pkt) = MutableEthernetPacket::new(&mut data) {
                let mut mac_src = eth_pkt.get_source();
                if !(mac_src.is_zero() || mac_src.is_broadcast() || mac_src.is_multicast()) {
                    mac_src.octet_increment(args.mac_octet_number);
                    eth_pkt.set_source(mac_src);
                }
                let mut mac_dst = eth_pkt.get_destination();
                if !(mac_dst.is_zero() || mac_dst.is_broadcast() || mac_dst.is_multicast()) {
                    mac_dst.octet_increment(args.mac_octet_number);
                    eth_pkt.set_destination(mac_dst);
                }
                if eth_pkt.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(mut ip4_pkt) = MutableIpv4Packet::new(eth_pkt.payload_mut()) {
                        let mut ip4_src = ip4_pkt.get_source();
                        if !(ip4_src.is_unspecified()
                            || ip4_src.is_loopback()
                            || ip4_src.is_multicast()
                            || ip4_src.is_broadcast())
                        {
                            ip4_src.octet_increment(args.ipv4_octet_number);
                            ip4_pkt.set_source(ip4_src);
                        }
                        let mut ip4_dst = ip4_pkt.get_destination();
                        if !(ip4_dst.is_unspecified()
                            || ip4_dst.is_loopback()
                            || ip4_dst.is_multicast()
                            || ip4_dst.is_broadcast())
                        {
                            ip4_dst.octet_increment(args.ipv4_octet_number);
                            ip4_pkt.set_destination(ip4_dst);
                        }
                    } else {
                        println!("Error getting ipv4 packet from ethernet frame on packet number (starting from 1): {}", packet_number);
                        println!("{:?} \n", pkt);
                    }
                }
                if eth_pkt.get_ethertype() == EtherTypes::Ipv6 {
                    //println!("ipv6");
                    if let Some(mut ip6_pkt) = MutableIpv6Packet::new(eth_pkt.payload_mut()) {
                        let mut ip6_src = ip6_pkt.get_source();
                        if !(ip6_src.is_loopback()
                            || ip6_src.is_unspecified()
                            || ip6_src.is_multicast())
                        {
                            ip6_src.octet_increment(args.ipv6_octet_number);
                            ip6_pkt.set_source(ip6_src);
                        }
                        let mut ip6_dst = ip6_pkt.get_destination();
                        if !(ip6_dst.is_loopback()
                            || ip6_dst.is_unspecified()
                            || ip6_dst.is_multicast())
                        {
                            ip6_dst.octet_increment(args.ipv6_octet_number);
                            ip6_pkt.set_destination(ip6_dst);
                        }
                    } else {
                        println!("Error getting ipv6 packet from ethernet frame on packet number (starting from 1): {}", packet_number);
                        println!("{:?} \n", pkt);
                    }
                }
                pcap_writer
                    .write_packet(&PcapPacket::new(
                        pkt.timestamp,
                        pkt.orig_len,
                        eth_pkt.packet(),
                    ))
                    .unwrap();
            } else {
                println!(
                    "Error getting ethernet packet pcap on packet number (starting from 1): {}",
                    packet_number
                );
                println!("{:?} \n", pkt);
            }
        }
    }
}
