---
id: "mdns"
license: "CC-BY-SA-4.0"
attribution: "Wikipedia contributors, Multicast DNS; see source page history"
codes: []
keywords_en: ["mdns", "multicast dns", "local name resolution"]
keywords_ro: ["mdns", "rezolvare nume locale", "dns multicast"]
source_url: "https://en.wikipedia.org/wiki/Multicast_DNS"
fetched_url: "https://en.wikipedia.org/w/api.php?action=query&format=json&formatversion=2&prop=extracts%7Crevisions&explaintext=1&exsectionformat=plain&rvprop=ids%7Ctimestamp&redirects=1&titles=Multicast+DNS"
revision: {"sha256": "66529c99e64bca14ca5e7b7629b8b36738d041bbd3d42984aeab2404d87d666b", "etag": null, "last_modified": null, "id": 1380339161, "timestamp": "2026-10-15T03:37:54Z", "title": "Multicast DNS"}
retrieved: "2026-11-07T23:19:54.810620+00:00"
title: "Multicast DNS"
language: "en"
---

## kb:mdns#1

Multicast DNS (mDNS) is a computer networking protocol that resolves hostnames to IP addresses within small networks that do not include a local name server. It is a zero-configuration service, using essentially the same programming interfaces, packet formats and operating semantics as unicast Domain Name System (DNS). It was designed to work as either a stand-alone protocol or compatible with standard DNS servers. mDNS uses IP multicast and User Datagram Protocol (UDP) packets and is implemented by Apple, Microsoft and most Linux distributions. mDNS can work in conjunction with DNS Service Discovery (DNS-SD), a companion zero-configuration networking technique specified separately in RFC 6763. History Multicast DNS was first proposed by Bill Woodcock and Bill Manning in the IETF in 2000, and was eventually published as standards-track RFC 6762 by Stuart Cheshire and Marc Krochmal thirteen years later. Implementations mDNS is implemented by Apple Bonjour, Microsoft since Windows 10 and by open-source Avahi software packages included in most Linux distributions. Although the Windows 10 implementation in earlier releases (version 1703) was limited to discovering networked printers, screen mirroring devices, wireless

## kb:mdns#2

speakers etc, subsequent releases (Windows 10 version 1903 and later) resolved hostnames as well. Protocol overview When an mDNS client needs to resolve a hostname, it sends an IP multicast query message that asks the host having that name to identify itself. That target machine then multicasts a message that includes its IP address. All machines in that subnet can then use that information to update their mDNS caches. Any host can relinquish its claim to a name by sending a response packet with a time to live (TTL) equal to zero. By default, mDNS exclusively resolves hostnames ending with the .local top-level domain. This can cause problems if .local includes hosts that do not implement mDNS but that can be found via a conventional unicast DNS server. Resolving such conflicts requires network-configuration changes that mDNS was designed to avoid. Packet structure An mDNS message is a multicast UDP packet sent using the following addressing: IPv4 address 224.0.0.251 or IPv6 address ff02::fb UDP port 5353 When using Ethernet frames, the standard IP multicast MAC address 01:00:5E:00:00:FB (for IPv4) or

## kb:mdns#3

33:33:00:00:00:FB (for IPv6) The payload structure is based on the unicast DNS packet format, consisting of two parts—the header and the data. The header is identical to that found in unicast DNS, as are the sub-sections in the data part: queries, answers, authoritative-nameservers, and additional records. The number of records in each sub-section matches the value of the corresponding *COUNT field in the header. Queries The wire format for records in the query section is slightly modified from that in unicast DNS, adding the single-bit UNICAST-RESPONSE field. As in unicast DNS, the QNAME field consists of a series of length/value sub-fields called labels. Each label represents one of the dot-separated substrings in a fully qualified domain name (FQDN). The list is terminated by either a single null-byte representing the root of the DNS, or by a byte with the two high-order bits set (value 192) to signal an indirect pointer to another location in the message. This is known as name compression in RFC 6762. The UNICAST-RESPONSE field is used to minimize unnecessary broadcasts on the network: if the

## kb:mdns#4

bit is set, responders SHOULD send a directed-unicast response directly to the inquiring node rather than broadcasting the response to the entire network. The QCLASS field is identical to that found in unicast DNS. Resource Records All records in the answers, authoritative-nameservers, and additional records sections have the same format and are collectively known as Resource Records (RR). Resource Records in mDNS also have a slightly modified general format compared to unicast DNS: The CACHE-FLUSH bit is used to instruct neighbor nodes that the record should overwrite, rather than be appended onto, any existing cached entries for this RRNAME and RRTYPE. The formats of the RDATA fields are the same as those found in unicast DNS. However, DNS Service Discovery (DNS-SD), the most common use-case for mDNS, specifies slight modifications to some of their formats (notably TXT records). See also Bonjour Sleep Proxy Link-Local Multicast Name Resolution (LLMNR) Name Service Switch (NSS) Simple Service Discovery Protocol (SSDP) References External links Multicast DNS - information site maintained by mDNS designer, Stuart Cheshire LLMNR, Multicast DNS and names on your LAN
