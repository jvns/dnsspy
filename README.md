# dnspeep

`dnspeep` lets you spy on the DNS queries your computer is making.

Here's some example output:

```
$ sudo dnspeep
query name                           server IP       response
A     incoming.telemetry.mozilla.org 192.168.1.1     CNAME: telemetry-incoming.r53-2.services.mozilla.com, CNAME: pipeline-incoming-prod-elb-149169523.us-west-2.elb.amazonaws.com, A: 52.39.144.189, A: 54.191.136.131, A: 34.215.151.143, A: 54.149.208.57, A: 44.226.235.191, A: 52.10.174.113, A: 35.160.138.173, A: 44.238.190.78
AAAA  incoming.telemetry.mozilla.org 192.168.1.1     CNAME: telemetry-incoming.r53-2.services.mozilla.com, CNAME: pipeline-incoming-prod-elb-149169523.us-west-2.elb.amazonaws.com
A     www.google.com                 192.168.1.1     A: 172.217.13.132
AAAA  www.google.com                 192.168.1.1     AAAA: 2607:f8b0:4020:807::2004
A     www.neopets.com                192.168.1.1     CNAME: r9c3n8d2.stackpathcdn.com, A: 151.139.128.11
AAAA  www.neopets.com                192.168.1.1     CNAME: r9c3n8d2.stackpathcdn.com
```

### experimental software warning

dnspeep is experimental and unmaintained, it definitely has bugs, I do not trust that its output is always correct

## How to install

You can install dnspeep using the different methods below.

### Installing the binary release

1. Download recent release of `dnspeep` from [the GitHub releases page](https://github.com/jvns/dnspeep/releases)
1. Unpack it
1. Put the `dnspeep` binary in your PATH (for example in `/usr/local/bin`)

### Compile and installing from source

1. Download recent source release of `dnspeep` from [the GitHub releases page](https://github.com/jvns/dnspeep/releases) or git clone this repository.
1. Unpack it
1. Run ```cargo build --release```
1. Change to the "target/release" directory there.
1. Put the `dnspeep` binary in your PATH (for example in `/usr/local/bin`)

### Installing from a Linux package manager

* If you are using Arch Linux, then you can install dnspeep from the [AUR](https://aur.archlinux.org/).

### How it works

It uses `libpcap` to capture packets on port 53, and then matches up DNS
request and response packets so that it can show the request and response
together on the same line.

It also tracks DNS queries which didn't get a response within 1 second and
prints them out with the response `<no response>`.

### Limitations

* Only supports the DNS query types supported by the `dns-message-parser` crate ([here's a list](https://docs.rs/dns-message-parser/0.6.0/dns_message_parser/rr/enum.RR.html))
* Doesn't support TCP DNS queries, only UDP
* It can't show DNS-over-HTTPS queries (because it would need to MITM the HTTPS connection)
