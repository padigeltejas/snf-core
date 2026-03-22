# Event Model Specification

Every piece of information SNF-Core extracts from the network is expressed as an **SnfEvent** — a structured, typed record serialized to a single NDJSON line. This document defines the complete event model.

---

## Output File Structure

An SNF-Core output file is a sequence of NDJSON records, one per line:

```
Line 1:    SessionHeader          — exactly one, always first
Line 2..N: SnfEvent              — one per extracted finding
```

This structure is designed for streaming consumption. You can `grep`, `jq`, or pipe the file without loading it entirely into memory.

```bash
# All TLS Client Hello events
grep '"event_type":"TlsClientHello"' events.ndjson | jq .

# All IOC matches
grep '"event_type":"intel.ioc_match"' events.ndjson | jq '.attributes'

# All events from a specific flow
grep '192.168.1.5:49200-185.220.101.1:443' events.ndjson

# Count events by type
jq -r '.event_type' events.ndjson | sort | uniq -c | sort -rn
```

---

## SessionHeader

The first line of every output file. Contains session metadata that applies to all subsequent events.

```json
{
  "record_type": "snf_session_header",
  "snf_version": "1.0.0",
  "session_start_us": 1700000000000000,
  "operating_mode": "forensic",
  "config_sha256": "a1b2c3d4e5f6...",
  "input_source": "capture.pcap",
  "pcap_sha256": "f6e5d4c3b2a1..."
}
```

| Field | Type | Description |
|---|---|---|
| `record_type` | string | Always `"snf_session_header"` |
| `snf_version` | string | SNF-Core version that produced this file |
| `session_start_us` | u64 | Session start timestamp (µs UTC, from first packet) |
| `operating_mode` | string | `forensic`, `monitor`, `stealth`, or `replay` |
| `config_sha256` | string | SHA-256 of the active configuration |
| `input_source` | string | PCAP filename or interface identifier |
| `pcap_sha256` | string | SHA-256 of the input PCAP file (PCAP mode only) |

---

## SnfEvent

All lines after the SessionHeader are SnfEvents.

```json
{
  "event_id": 1,
  "packet_id": 42,
  "timestamp_us": 1700000123456789,
  "event_type": "TlsClientHello",
  "protocol": "TLS",
  "flow_id": "192.168.1.5:49200-185.220.101.1:443-TCP",
  "attributes": {
    "alpn": "h2",
    "ja3": "771,49196-49200-...",
    "ja3_hash": "e6573e91e6eb777c0933c5b8f97f10cd",
    "ja3_label": "Firefox_107",
    "sni": "example.com",
    "tls_version": "TLS1.3"
  }
}
```

### Mandatory Fields

Every SnfEvent contains exactly these 7 fields:

| Field | Type | Description |
|---|---|---|
| `event_id` | u64 | Sequential ID within this session, starts at 1 |
| `packet_id` | u64 | Position of the triggering packet in the PCAP file |
| `timestamp_us` | u64 | Packet timestamp in microseconds UTC (from PCAP header) |
| `event_type` | string | Event type identifier — see Event Types below |
| `protocol` | string | Protocol that generated the event |
| `flow_id` | string | Normalized 5-tuple flow identifier |
| `attributes` | object | Protocol-specific typed key/value pairs |

### Flow ID Format

```
{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}

Examples:
  192.168.1.5:49200-8.8.8.8:53-UDP
  10.0.0.1:52341-185.220.101.1:443-TCP
  192.168.1.1:0-192.168.1.255:0-ICMP
```

Flow IDs are normalized: for TCP/UDP, the lower IP:port pair is always first. This ensures that forward and reverse traffic for the same flow share the same flow ID.

---

## Event Types

### Network Events

| Event Type | Protocol | Trigger |
|---|---|---|
| `DnsQuery` | DNS | DNS query packet |
| `DnsResponse` | DNS | DNS response packet |
| `TlsClientHello` | TLS | TLS ClientHello message |
| `TlsServerHello` | TLS | TLS ServerHello message |
| `HttpRequest` | HTTP | HTTP request line |
| `HttpResponse` | HTTP | HTTP status line |
| `QuicSni` | QUIC | QUIC Client Initial with SNI |
| `DhcpMessage` | DHCP | Any DHCP message |
| `IcmpMessage` | ICMP | ICMP/ICMPv6 packet |
| `SmbSession` | SMB | SMB command |
| `MdnsRecord` | mDNS | mDNS query or response |
| `DohDetected` | DNS | DNS-over-HTTPS pattern |
| `DotDetected` | TLS | DNS-over-TLS on port 853 |

### ICS/SCADA Events

| Event Type | Protocol |
|---|---|
| `IcsModbus` | Modbus |
| `IcsDnp3` | DNP3 |
| `IcsS7` | S7comm |
| `IcsEnip` | EtherNet/IP + CIP |
| `IcsProfinet` | PROFINET |

### LAN Discovery Events

| Event Type | Protocol |
|---|---|
| `LanLldp` | LLDP |
| `LanCdp` | CDP |

### Enterprise Events

| Event Type | Protocol |
|---|---|
| `EnterpriseKerberos` | Kerberos |
| `EnterpriseLdap` | LDAP |
| `EnterpriseRdp` | RDP |

### Discovery Events

| Event Type | Protocol |
|---|---|
| `DiscoverySsdp` | SSDP/UPnP |
| `DiscoveryFtp` | FTP |

### Threat Intelligence Events

| Event Type | Protocol | Trigger |
|---|---|---|
| `intel.ioc_match` | IOC | IP or domain matched offline blocklist |
| `intel.threat_match` | TLS | JA3/JA4 fingerprint matched malicious database |

### Flow Events

| Event Type | Trigger |
|---|---|
| `FlowNew` | First packet of a new flow |
| `FlowEnd` | Flow expired or evicted from FlowTable |

### Capture Events

| Event Type | Trigger |
|---|---|
| `capture.drop` | Packets dropped due to queue overflow |

---

## Attribute Value Types

Attributes are typed. The type determines how values are serialized to JSON:

| SNF Type | JSON | Example | Notes |
|---|---|---|---|
| `attr_u64(key, v)` | number | `"ttl": 300` | All integers and counts |
| `attr_str(key, v)` | string | `"sni": "example.com"` | All strings, formatted values |
| `attr_u16(key, v)` | number | `"dst_port": 443` | Port numbers |
| `attr_u8(key, v)` | number | `"icmp_type": 8` | Byte values |
| `attr_bool(key, v)` | boolean | `"session_resumed": false` | Flags |
| `attr_ip(key, v)` | string | `"resolved_ip": "8.8.8.8"` | IP addresses |
| `attr_u16_list(key, v)` | number[] | `"cipher_suites": [49196, 49200]` | Cipher suite lists |
| `attr_str_list(key, v)` | string[] | `"cname_chain": ["a.com", "b.com"]` | String lists |

**`AttrValue::Int` and `AttrValue::Float` do not exist.** Use `attr_u64()` for integers and `attr_str()` for formatted floats.

Attributes within each event are serialized in **alphabetical key order** (via `BTreeMap`). This is part of the determinism guarantee — attribute order is always predictable and stable.

---

## Complete Examples

### DNS Query + Response

```json
{"event_id":1,"packet_id":10,"timestamp_us":1700000000100000,"event_type":"DnsQuery","protocol":"DNS","flow_id":"192.168.1.5:52341-8.8.8.8:53-UDP","attributes":{"is_response":false,"query_name":"malware-c2.example.com","record_type":"A"}}

{"event_id":2,"packet_id":11,"timestamp_us":1700000000150000,"event_type":"DnsResponse","protocol":"DNS","flow_id":"192.168.1.5:52341-8.8.8.8:53-UDP","attributes":{"is_response":true,"query_name":"malware-c2.example.com","record_type":"A","resolved_ip":"185.220.101.1","ttl":60}}
```

### TLS ClientHello with JA3 Match

```json
{"event_id":3,"packet_id":15,"timestamp_us":1700000000200000,"event_type":"TlsClientHello","protocol":"TLS","flow_id":"192.168.1.5:49200-185.220.101.1:443-TCP","attributes":{"alpn":"none","cipher_suites":[49196,49200,159,158,49188,49192,107,106],"ja3":"771,49196-49200-159-158...","ja3_hash":"e6573e91e6eb777c0933c5b8f97f10cd","ja3_label":"CobaltStrike_default","session_resumed":false,"sni":"185.220.101.1","tls_version":"TLS1.2"}}
```

### IOC IP Match

```json
{"event_id":4,"packet_id":15,"timestamp_us":1700000000200000,"event_type":"intel.ioc_match","protocol":"IOC","flow_id":"192.168.1.5:49200-185.220.101.1:443-TCP","attributes":{"confidence":"95","direction":"dst","ioc_type":"ip","label":"Emotet_C2_epoch3","matched_ip":"185.220.101.1","threat_actor":"Emotet"}}
```

### JA3 Threat Match

```json
{"event_id":5,"packet_id":15,"timestamp_us":1700000000200000,"event_type":"intel.threat_match","protocol":"TLS","flow_id":"192.168.1.5:49200-185.220.101.1:443-TCP","attributes":{"fingerprint_type":"ja3","hash":"e6573e91e6eb777c0933c5b8f97f10cd","label":"CobaltStrike_default","threat_actor":"Cobalt Strike"}}
```

### Modbus Read Holding Registers

```json
{"event_id":6,"packet_id":22,"timestamp_us":1700000001000000,"event_type":"IcsModbus","protocol":"Modbus","flow_id":"192.168.1.100:1024-192.168.1.200:502-TCP","attributes":{"modbus_exception":false,"modbus_function_code":3,"modbus_register_addr":100,"modbus_register_count":10,"modbus_unit_id":1}}
```

---

## Consuming NDJSON Output

### Python

```python
import json

with open("snf_events.ndjson") as f:
    for line in f:
        event = json.loads(line)
        if event.get("event_type") == "intel.ioc_match":
            attrs = event["attributes"]
            print(f"IOC hit: {attrs['matched_ip']} — {attrs['threat_actor']}")
```

### jq

```bash
# Extract all IOC hits as CSV
jq -r 'select(.event_type == "intel.ioc_match") | [.flow_id, .attributes.ioc_type, .attributes.label, .attributes.threat_actor] | @csv' events.ndjson

# Count TLS handshakes per SNI
jq -r 'select(.event_type == "TlsClientHello") | .attributes.sni' events.ndjson | sort | uniq -c | sort -rn

# All events on a specific flow
jq 'select(.flow_id == "192.168.1.5:49200-185.220.101.1:443-TCP")' events.ndjson
```

### Splunk / Elastic

The NDJSON format ingests directly into Splunk (as JSON sourcetype) or Elasticsearch (via Filebeat or direct bulk API). The `flow_id`, `timestamp_us`, and `event_type` fields index cleanly as structured fields.

---

## Schema Stability

The event schema follows semantic versioning:
- **Minor versions** may add new event types and new optional attributes — fully backward compatible
- **Major versions** may rename or remove fields — migration guide provided
- The `snf_version` field in `SessionHeader` identifies the schema version that produced the file
