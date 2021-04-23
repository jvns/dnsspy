use bytes::Bytes;
use chrono::{DateTime, Utc};
use dns_message_parser::rr::RR;
use dns_message_parser::DecodeError;
use dns_message_parser::Dns;
use etherparse::IpHeader;
use etherparse::PacketHeaders;
use eyre::{Result, WrapErr};
#[cfg(not(windows))]
use futures::StreamExt;
use getopts::Options;
use hex::encode;
#[cfg(not(windows))]
use pcap::stream::{PacketCodec, PacketStream};
#[cfg(not(windows))]
use pcap::Active;
use pcap::{Capture, Device, Linktype, Packet};
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::str;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use std::time;
use tokio::time::{delay_for, Duration};

#[derive(Clone)]
struct OrigPacket {
    qname: String,
    typ: String,
    server_ip: String,
    server_port: u16,
    has_response: bool,
    timestamp: DateTime<Utc>,
}

#[derive(Clone)]
struct Opts {
    source: Source,
    timestamp: bool,
}

#[derive(Clone)]
struct Interface {
    device: Device,
    port: u16,
}

fn find_device_with_name(name: &str) -> Result<Option<Device>> {
    let device = pcap::Device::list()?
        .iter()
        .filter(|x| x.name.eq(name))
        .nth(0)
        .map(|x| x.to_owned());

    Ok(device)
}

impl Interface {
    #[cfg(windows)]
    fn from_default() -> Result<Interface> {
        let device = pcap::Device::lookup().wrap_err("Cannot find any interface on your device")?;
        // pcap doesn't return the device's desc in `lookup` method.
        // Using unwrap is safe here since we have gotten the correct name.
        let device = find_device_with_name(&device.name)?.unwrap();

        Ok(Interface::from_device(device))
    }

    #[cfg(not(windows))]
    fn from_any() -> Result<Interface> {
        let device = find_device_with_name("any").wrap_err("Cannot find the interface `any`")?;
        match device {
            Some(dev) => Ok(Interface::from_device(dev)),
            None => panic!("Cannot find the interface `any`"),
        }
    }

    fn from_device(device: Device) -> Interface {
        Interface { device, port: 53 }
    }
}

#[derive(Clone)]
enum Source {
    Interface(Interface),
    Filename(String),
}

impl Opts {
    fn print_source(self: &Opts) {
        match &self.source {
            Source::Interface(iter) => {
                let name = &iter.device.name;
                let desc = iter
                    .device
                    .desc
                    .as_ref()
                    .map(|desc| format!("({})", desc))
                    .unwrap_or(String::from(""));
                let port = iter.port;
                println!("Capturing from interface {}{} at port {}", name, desc, port)
            }
            Source::Filename(filename) => {
                println!("Capturing from file {}", filename)
            }
        }
    }
    fn print_header(self: &Opts) {
        if self.timestamp {
            println!(
                "{:14} {:5} {:30} {:20} {:9} {}",
                "timestamp", "query", "name", "server IP", "elapsed", "response"
            );
        } else {
            println!(
                "{:5} {:30} {:20} {}",
                "query", "name", "server IP", "response"
            );
        }
    }
    fn print_response(self: &Opts, packet: &OrigPacket, elapsed_time: &str, response: &str) {
        if self.timestamp {
            println!(
                "{:14} {:5} {:30} {:20} {:9} {}",
                packet.timestamp.format("%H:%M:%S%.3f"),
                packet.typ,
                packet.qname,
                packet.server_ip,
                elapsed_time,
                response
            );
        } else {
            println!(
                "{:5} {:30} {:20} {}",
                packet.typ, packet.qname, packet.server_ip, response
            );
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let map = Arc::new(Mutex::new(HashMap::new()));
    let opts = parse_args()?;
    opts.print_source();
    opts.print_header();

    match opts.clone().source {
        Source::Interface(interface) => {
            #[cfg(windows)]
            {
                capture_interface(interface, map, opts)?
            }

            #[cfg(not(windows))]
            {
                let stream = capture_stream(opts, map, interface)?;
                capture_packets(stream).await;
            }
        }
        Source::Filename(filename) => {
            capture_file(&opts, &filename)?;
        }
    };
    Ok(())
}

fn parse_args() -> Result<Opts> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("p", "port", "port number to listen on", "PORT");
    opts.optopt("f", "file", "read packets from pcap file", "FILENAME");
    opts.optflag(
        "t",
        "timestamp",
        "print timestamp and elapsed time for each query",
    );
    opts.optflag("h", "help", "print this help menu");
    opts.optopt(
        "i",
        "interface",
        "capture packets from an interface",
        "INTERFACE_NAME",
    );
    opts.optflag("l", "list", "list all interfaces");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!(f.to_string())
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        std::process::exit(0);
    }

    if matches.opt_present("l") {
        list_all_interfaces()?;
        std::process::exit(0);
    }

    let mut opts = Opts {
        #[cfg(windows)]
        source: Source::Interface(Interface::from_default()?),
        #[cfg(not(windows))]
        source: Source::Interface(Interface::from_any()?),
        timestamp: matches.opt_present("t"),
    };

    if let Some(interface_name) = matches.opt_str("i") {
        match find_device_with_name(&interface_name)? {
            Some(device) => {
                opts.source = Source::Interface(Interface::from_device(device));
            }
            None => {
                eprintln!(
                    "Cannot find an interface with the name `{}`",
                    &interface_name
                );
                std::process::exit(1);
            }
        }
    } else if let Some(filename) = matches.opt_str("f") {
        opts.source = Source::Filename(filename.to_string());
    }
    if let Some(port_str) = matches.opt_str("p") {
        match port_str.parse() {
            // set port to current interface config
            Ok(port) => match &mut opts.source {
                Source::Interface(iter) => iter.port = port,
                _ => {}
            },
            Err(_) => {
                eprintln!("Invalid port number: {}", &port_str);
                std::process::exit(1);
            }
        }
    }
    Ok(opts)
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
    println!("
What the output columns mean:
   query:     DNS query type (A, CNAME, etc)
   name:      Hostname the DNS query is requesting
   server IP: IP address of the DNS server the query was made to
   elapsed:   How long the DNS response took to arrive
   response:  Responses from the Answer section of the DNS response (or \"<no response>\" if none was found).
              Multiple responses are separated by commas.
");
}

fn capture_file(opts: &Opts, filename: &str) -> Result<()> {
    let mut map = HashMap::new();
    let mut cap = Capture::from_file(filename).wrap_err("Failed to start capture from file")?;
    let linktype = cap.get_datalink();
    while let Ok(packet) = cap.next() {
        if let Err(e) = print_packet(opts, packet, linktype, &mut map) {
            // Continue if there's an error, but print a warning
            eprintln!("Error parsing DNS packet: {:#}", e);
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn capture_stream(
    opts: Opts,
    map: Arc<Mutex<HashMap<u16, OrigPacket>>>,
    interface: Interface,
) -> Result<PacketStream<Active, PrintCodec>> {
    let mut cap = Capture::from_device(interface.device)
        .wrap_err("Failed to find device 'any'")?
        .immediate_mode(true)
        .open()
        .wrap_err("Failed to start. This may be because you need to run this as root.")?
        .setnonblock()
        .wrap_err("Failed to set nonblocking")?;
    let linktype = cap.get_datalink();
    cap.filter(format!("udp and port {}", interface.port).as_str(), true)
        .wrap_err("Failed to create BPF filter")?;
    cap.stream(PrintCodec {
        map,
        linktype,
        opts: opts,
    })
    .wrap_err("Failed to create stream")
}

#[cfg(not(windows))]
async fn capture_packets(mut stream: PacketStream<Active, PrintCodec>) {
    while stream.next().await.is_some() {}
}

#[cfg(windows)]
fn capture_interface(
    interface: Interface,
    map: Arc<Mutex<HashMap<u16, OrigPacket>>>,
    opts: Opts,
) -> Result<()> {
    let mut cap = pcap::Capture::from_device(interface.device)
        .wrap_err("Failed to find the interface")?
        .immediate_mode(true)
        .open()
        .wrap_err("Failed to start.")?;

    cap.filter(format!("udp and port {}", interface.port).as_str(), true)
        .expect("Failed to create BPF filter");

    let mut decoder = PrintCodec {
        map,
        linktype: cap.get_datalink(),
        opts,
    };

    while let Ok(packet) = cap.next() {
        decoder.decode_packet(packet)?
    }

    Ok(())
}

fn list_all_interfaces() -> Result<()> {
    let empty_str = "".to_string();

    let interfaces =
        pcap::Device::list().wrap_err("Encounter error while listing interfaces on your device")?;
    println!("{:55} {}", "Interface Name", "Interface Description");
    interfaces.iter().for_each(|it| {
        let name = &it.name;
        let desc = it.desc.as_ref().unwrap_or(&empty_str);
        println!("{:55} {}", name, desc);
    });

    Ok(())
}

pub struct PrintCodec {
    map: Arc<Mutex<HashMap<u16, OrigPacket>>>,
    linktype: Linktype,
    opts: Opts,
}

impl PrintCodec {
    pub fn decode_packet(&mut self, packet: Packet) -> Result<(), pcap::Error> {
        let mut map = self.map.lock().unwrap();
        let map_clone = self.map.clone();
        let opts_clone = self.opts.clone();
        match print_packet(&self.opts, packet, self.linktype, &mut *map) {
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
}

#[cfg(not(windows))]
impl PacketCodec for PrintCodec {
    type Type = ();

    fn decode(&mut self, packet: Packet) -> Result<(), pcap::Error> {
        self.decode_packet(packet)
    }
}

fn get_time(packet: &Packet) -> DateTime<Utc> {
    let packet_time = packet.header.ts;
    let micros = (packet_time.tv_sec as u64 * 1000000) + (packet_time.tv_usec as u64);
    DateTime::<Utc>::from(time::UNIX_EPOCH + time::Duration::from_micros(micros))
}

fn print_packet(
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

fn format_answers(records: Vec<RR>) -> String {
    let formatted: Vec<String> = records.iter().map(|x| format_record(&x)).collect();
    formatted.join(", ")
}

fn format_record(rdata: &RR) -> String {
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
