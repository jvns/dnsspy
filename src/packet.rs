use super::Opts;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use dns_message_parser::rr::RR;
use dns_message_parser::DecodeError;
use dns_message_parser::Dns;
use etherparse::IpHeader;
use etherparse::PacketHeaders;
use eyre::{Result, WrapErr};
use hex::encode;
#[cfg(not(windows))]
use pcap::stream::PacketCodec;
use pcap::{Linktype, Packet};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use std::time;
use tokio::time::{delay_for, Duration};

#[derive(Clone)]
pub struct OrigPacket {
    pub qname: String,
    pub typ: String,
    pub server_ip: String,
    pub server_port: u16,
    pub has_response: bool,
    pub timestamp: DateTime<Utc>,
}

pub struct PrintCodec {
    pub map: Arc<Mutex<HashMap<u16, OrigPacket>>>,
    pub linktype: Linktype,
    pub opts: Opts,
}

fn decode(codec: &PrintCodec, packet: Packet) -> Result<(), pcap::Error> {
    let mut map = codec.map.lock().unwrap();
    let map_clone = codec.map.clone();
    let opts_clone = codec.opts.clone();
    match print_packet(&codec.opts, packet, codec.linktype, &mut *map) {
        Ok(Some(id)) => {
            // This means we just got a new query we haven't seen before.
            // After 1 second, remove from the map and print '<no response>' if there was no
            // response yet
            tokio::spawn(async move {
                delay_for(Duration::from_millis(1000)).await;
                let mut map = map_clone.lock().unwrap();
                if let Some(packet) = map.get(&id) {
                    if packet.has_response == false {
                        opts_clone.print_response(&packet, "", "<no response>");
                    }
                }
                map.remove(&id);
            });
        }
        Err(e) => {
            // Continue if there's an error, but print a warning
            eprintln!("Error parsing DNS packet: {:#}", e);
        }
        _ => {}
    }
    Ok(())
}

pub fn get_time(packet: &Packet) -> DateTime<Utc> {
    let packet_time = packet.header.ts;
    let micros = (packet_time.tv_sec as u64 * 1000000) + (packet_time.tv_usec as u64);
    DateTime::<Utc>::from(time::UNIX_EPOCH + time::Duration::from_micros(micros))
}

pub fn print_packet(
    opts: &Opts,
    orig_packet: Packet,
    linktype: Linktype,
    map: &mut HashMap<u16, OrigPacket>,
) -> Result<Option<u16>> {
    // Strip the ethernet header
    let packet_data = match linktype {
        Linktype::ETHERNET => &orig_packet.data[14..],
        Linktype::LINUX_SLL => &orig_packet.data[16..],
        Linktype::LINUX_SLL2 => &orig_packet.data[20..],
        Linktype::IPV4 => &orig_packet.data,
        Linktype::IPV6 => &orig_packet.data,
        Linktype::NULL => &orig_packet.data[4..],
        Linktype(12) => &orig_packet.data,
        Linktype(14) => &orig_packet.data,
        _ => panic!("unknown link type {:?}", linktype),
    };
    // Parse the IP header and UDP header
    let packet =
        PacketHeaders::from_ip_slice(packet_data).wrap_err("Failed to parse Ethernet packet")?;
    let (_src_ip, dest_ip): (IpAddr, IpAddr) =
        match packet.ip.expect("Error: failed to parse IP address") {
            IpHeader::Version4(x) => (x.source.into(), x.destination.into()),
            IpHeader::Version6(x) => (x.source.into(), x.destination.into()),
        };
    let udp_header = packet
        .transport
        .expect("Error: Expected transport header")
        .udp()
        .expect("Error: Expected UDP packet");
    // Parse DNS data
    let dns_packet = match Dns::decode(Bytes::copy_from_slice(packet.payload)) {
        Ok(dns) => dns,
        Err(DecodeError::RemainingBytes(_, dns)) => dns,
        x => x.wrap_err("Failed to parse DNS packet")?,
    };
    let id = dns_packet.id;
    // The map is a list of queries we've seen in the last 1 second
    // Decide what to do depending on whether this is a query and whether we've seen that ID
    // recently
    match (dns_packet.flags.qr == false, map.contains_key(&id)) {
        (true, false) => {
            // It's a new query, track it
            let question = &dns_packet.questions[0];
            map.insert(
                id,
                OrigPacket {
                    timestamp: get_time(&orig_packet),
                    typ: format!("{:?}", question.q_type),
                    qname: question.domain_name.to_string(),
                    server_ip: format!("{}", dest_ip),
                    server_port: udp_header.destination_port,
                    has_response: false,
                },
            );
            Ok(Some(id))
        }
        (true, true) => {
            // A query we've seen before is a retry, ignore it
            Ok(None)
        }
        (false, false) => {
            // A response we haven't seen the query for
            eprintln!("Warning: got response for unknown query ID {}", id);
            Ok(None)
        }
        (false, true) => {
            map.entry(id).and_modify(|e| e.has_response = true);
            // It's a response for a query we remember, so format it and print it out
            let query_packet = map.get(&id).unwrap();
            let response = if !dns_packet.answers.is_empty() {
                format_answers(dns_packet.answers)
            } else {
                dns_packet.flags.rcode.to_string().to_uppercase()
            };
            let ms = (get_time(&orig_packet) - query_packet.timestamp).num_milliseconds();
            opts.print_response(query_packet, &format!("{}ms", ms), &response);
            Ok(None)
        }
    }
}

pub fn format_answers(records: Vec<RR>) -> String {
    let formatted: Vec<String> = records.iter().map(|x| format_record(&x)).collect();
    formatted.join(", ")
}

pub fn format_record(rdata: &RR) -> String {
    match rdata {
        RR::A(x) => format!("A: {}", x.ipv4_addr),
        RR::AAAA(x) => format!("AAAA: {}", x.ipv6_addr),
        RR::AFSDB(x) => format!("AFSDB: {} {}", x.subtype, x.hostname),
        RR::APL(x) => {
            // not in use
            let formatted: Vec<String> = x.apitems.iter().map(|x| x.to_string()).collect();
            format!("APL: {}", formatted.join(" "))
        }
        RR::CAA(x) => format!(
            "CAA: {} {} {}",
            x.flags,
            x.tag,
            from_utf8(&x.value).unwrap() // TODO: do better error handling here than an unwrap()
        ),
        RR::CNAME(x) => format!("CNAME: {}", x.c_name),
        RR::DNAME(x) => format!("DNAME: {}", x.target),
        RR::DNSKEY(x) => format!(
            "DNSKEY: 3 {} {} {}",
            x.get_flags(),
            x.algorithm_type.clone() as u8,
            encode(&x.public_key),
        ),
        RR::DS(x) => format!(
            "DS: {} {} {} {}",
            x.key_tag,
            x.algorithm_type,
            x.digest_type,
            encode(&x.digest),
        ),
        RR::EID(x) => format!("EID: {}", from_utf8(&x.data).unwrap()), // not in use
        RR::EUI48(x) => format!(
            "EUI48: {:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            x.eui_48[0], x.eui_48[1], x.eui_48[2], x.eui_48[3], x.eui_48[4], x.eui_48[5],
        ),
        RR::EUI64(x) => format!(
            "EUI64: {:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            x.eui_64[0],
            x.eui_64[1],
            x.eui_64[2],
            x.eui_64[3],
            x.eui_64[4],
            x.eui_64[5],
            x.eui_64[6],
            x.eui_64[7],
        ),
        RR::GPOS(x) => format!("GPOS: {} {} {}", x.latitude, x.longitude, x.altitude),
        RR::HINFO(x) => format!("HINFO: {} {}", x.cpu, x.os),
        RR::ISDN(x) => format!("ISDN: {}", x.isdn_address),
        RR::KX(x) => format!("KX: {} {}", x.preference, x.exchanger),
        RR::L32(x) => {
            let bytes = x.locator_32.to_be_bytes();
            format!(
                "L32: {} {} {} {} {}",
                x.preference, bytes[0], bytes[1], bytes[2], bytes[3]
            )
        }
        RR::L64(x) => format!("L64: {} {}", x.preference, x.locator_64),
        RR::LOC(x) => format!(
            "LOC: {} {} {} {} {} {}",
            x.size, x.horiz_pre, x.vert_pre, x.latitube, x.longitube, x.altitube
        ),
        RR::LP(x) => format!("LP: {} {}", x.preference, x.fqdn),
        RR::MB(x) => format!("MB: {}", x.mad_name),
        RR::MD(x) => format!("MD: {}", x.mad_name),
        RR::MF(x) => format!("MF: {}", x.mad_name),
        RR::MG(x) => format!("MG: {}", x.mgm_name),
        RR::MINFO(x) => format!("MINFO: {} {}", x.r_mail_bx, x.e_mail_bx),
        RR::MR(x) => format!("MR: {}", x.new_name),
        RR::MX(x) => format!("MX: {} {}", x.preference, x.exchange),
        RR::NID(x) => format!("NID: {} {}", x.preference, x.node_id),
        RR::NIMLOC(x) => format!("NIMLOC: {}", from_utf8(&x.data).unwrap()), // not in use
        RR::NS(x) => format!("NS: {}", x.ns_d_name),
        RR::NSAP(x) => format!("NSAP: {}", from_utf8(&x.data).unwrap()), // not in use
        RR::NULL(x) => format!("NULL: {}", from_utf8(&x.data).unwrap()),
        RR::OPT(_) => panic!("didn't expect to see an OPT record in the answer section"),
        RR::PTR(x) => format!("PTR: {}", x.ptr_d_name),
        RR::PX(x) => format!("PX: {} {} {}", x.preference, x.map822, x.mapx400), // not in use
        RR::RP(x) => format!("RP: {} {}", x.mbox_dname, x.txt_dname),
        RR::RT(x) => format!("RT: {} {}", x.preference, x.intermediate_host),
        RR::SOA(x) => format!("SOA:{}...", x.m_name),
        RR::SRV(x) => format!("SRV: {} {} {} {}", x.priority, x.weight, x.port, x.target),
        RR::SSHFP(x) => format!(
            "SSHFP: {} {} {}",
            x.algorithm,
            x.type_,
            encode(x.fp.as_slice())
        ),
        RR::TXT(x) => format!("TXT: {}", x.string),
        RR::URI(x) => format!("URI: {} {} {}", x.priority, x.weight, x.uri),
        RR::WKS(x) => format!("WKS: {} {:x?}", x.protocol, x.bit_map),
        RR::X25(x) => format!("X25: {}", x.psdn_address), // not in use
    }
}

#[cfg(windows)]
impl PrintCodec {
    pub fn decode(&self, packet: Packet) -> Result<(), pcap::Error> {
        decode(self, packet)
    }
}

#[cfg(not(windows))]
impl PacketCodec for PrintCodec {
    type Type = ();

    fn decode(&mut self, packet: Packet) -> Result<(), pcap::Error> {
        decode(self, packet)
    }
}