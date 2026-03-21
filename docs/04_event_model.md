# Event Model Specification

## SessionHeader (line 1 of every output)
```json
{"record_type":"snf_session_header","snf_version":"1.0.0","session_start_us":1234567890,"operating_mode":"forensic","config_sha256":"abc...","input_source":"capture.pcap","pcap_sha256":"def..."}
```

## SnfEvent (all subsequent lines)
```json
{"event_id":1,"packet_id":42,"timestamp_us":1234567890123,"event_type":"DnsQuery","protocol":"DNS","flow_id":"1.2.3.4:52341-8.8.8.8:53-UDP","attributes":{"query_name":"example.com","is_response":false}}
```

## Mandatory Fields
| Field | Type | Description |
|---|---|---|
| event_id | u64 | Sequential, starts at 1 |
| packet_id | u64 | PCAP file order position |
| timestamp_us | u64 | Microseconds UTC from PCAP header |
| event_type | string | See EventType variants in src/core/event.rs |
| protocol | string | DNS, TLS, HTTP, QUIC, DHCP, ICMP, SMB, mDNS, etc. |
| flow_id | string | {min_ip}:{port}-{max_ip}:{port}-{proto} |
| attributes | object | Protocol-specific key/value pairs |

## AttrValue Types
- U64 — all integers and counts
- Str — all strings and formatted floats
- U16 — port numbers
- U8 — byte values
- Bool — flags
- Ip — IP addresses
- U16List — cipher suite lists
- StrList — CNAME chains, SANs

AttrValue::Int and AttrValue::Float do NOT exist.
