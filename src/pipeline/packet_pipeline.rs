// src/pipeline/packet_pipeline.rs
//
// Packet processing pipeline Ã¢â‚¬â€ the central coordinator.
//
// Phase 9E: Userspace packet filters enforced before any processing:
//   - min/max packet size
//   - exclude_loopback / exclude_multicast / exclude_broadcast
//   - protocol_filter
//   - ip_filter / src_ip_filter / dst_ip_filter / exclude_ips
//   - port_filter / src_port_filter / dst_port_filter / exclude_ports
//   Note: bpf_filter is applied at kernel level (pcap crate) Ã¢â‚¬â€ not re-evaluated here.
//
// Phase 9F: rebind_domains() throttled Ã¢â‚¬â€ no longer called on every packet.
//   - Called immediately on DNS responses (dns_is_response = true).
//   - Called as background sweep every REBIND_INTERVAL_PACKETS packets.
//   - Eliminates O(f * packets) hot path cost.
//
// Reliability pass (preserved): DNS/DHCP/mDNS cache bindings.
// Phase 5 (preserved): emit_protocol_events(), suppress_flow_updates.
// Phase 2 (preserved): parse error collection, TCP reassembly.

use crate::core::packet_context::PacketContext;
use crate::core::analyzer_manager::AnalyzerManager;
use crate::core::event_bus::EventBus;
use crate::core::event::{SnfEvent, EventType};
use crate::flow::flow_table::FlowTable;
use crate::discovery::dns_cache::DnsCache;
use crate::config::engine_config::EngineConfig;
use crate::dataset::ports;
use crate::core::flow_key::normalize_flow;
use crate::pipeline::tcp_reassembly::{TcpReassembler, ReassemblyResult};
#[allow(unused_imports)]
use std::net::IpAddr;
use std::str::FromStr;

/// How many packets between each expire_flows() + evict_idle_streams() sweep.
const EXPIRE_INTERVAL_PACKETS: u64 = 256;

/// How many packets between background rebind_domains() sweeps.
/// DNS-triggered rebinding fires immediately regardless of this interval.
const REBIND_INTERVAL_PACKETS: u64 = 1_000;

/// Flow idle timeout in microseconds (120 seconds).
const FLOW_IDLE_TIMEOUT_US: u64 = 120 * 1_000_000;

pub struct PacketPipeline {
    packet_counter: u64,
    tcp_reassembler: TcpReassembler,
}

impl PacketPipeline {
    pub fn new() -> Self {
        Self {
            packet_counter: 0,
            tcp_reassembler: TcpReassembler::new(),
        }
    }

    pub fn process_packet(
        &mut self,
        ctx: &mut PacketContext,
        payload: &[u8],
        tcp_seq: Option<u32>,
        config: &EngineConfig,
        flow_table: &mut FlowTable,
        dns_cache: &mut DnsCache,
        ports_db: &std::collections::HashMap<u16, String>,
        analyzer_manager: &mut AnalyzerManager,
        event_bus: &mut Option<EventBus>,
    ) {
        self.packet_counter = self.packet_counter.wrapping_add(1);

        // ================================================================
        // PHASE 9E Ã¢â‚¬â€ USERSPACE PACKET FILTERS
        // Applied before flow table lookup, protocol analysis, or any alloc.
        // Every filtered packet exits here Ã¢â‚¬â€ zero downstream cost.
        // ================================================================

        // ---- Packet size filters ----
        if config.filter.min_packet_size > 0
            && ctx.packet_size < config.filter.min_packet_size
        {
            return;
        }
        if config.filter.max_packet_size_filter > 0
            && ctx.packet_size > config.filter.max_packet_size_filter
        {
            return;
        }

        // ---- Loopback exclusion ----
        if config.filter.exclude_loopback {
            if is_loopback(ctx.src_ip) || is_loopback(ctx.dst_ip) {
                return;
            }
        }

        // ---- Multicast exclusion ----
        if config.filter.exclude_multicast && is_multicast(ctx.dst_ip) {
            return;
        }

        // ---- Broadcast exclusion ----
        if config.filter.exclude_broadcast && is_broadcast(ctx.dst_ip) {
            return;
        }

        // ---- Protocol filter ----
        if let Some(ref proto_filter) = config.filter.protocol_filter {
            if !ctx.protocol.eq_ignore_ascii_case(proto_filter) {
                return;
            }
        }

        // ---- IP filters ----
        if let Some(ref ip_str) = config.filter.ip_filter {
            if let Ok(filter_ip) = ip_str.parse::<IpAddr>() {
                if ctx.src_ip != filter_ip && ctx.dst_ip != filter_ip {
                    return;
                }
            }
        }
        if let Some(ref ip_str) = config.filter.src_ip_filter {
            if let Ok(filter_ip) = ip_str.parse::<IpAddr>() {
                if ctx.src_ip != filter_ip {
                    return;
                }
            }
        }
        if let Some(ref ip_str) = config.filter.dst_ip_filter {
            if let Ok(filter_ip) = ip_str.parse::<IpAddr>() {
                if ctx.dst_ip != filter_ip {
                    return;
                }
            }
        }

        // ---- Exclude IP list ----
        for ip_str in &config.filter.exclude_ips {
            if let Ok(excl_ip) = ip_str.parse::<IpAddr>() {
                if ctx.src_ip == excl_ip || ctx.dst_ip == excl_ip {
                    return;
                }
            }
        }

        // ---- Port filters ----
        if let Some(port_filter) = config.filter.port_filter {
            if ctx.src_port != port_filter && ctx.dst_port != port_filter {
                return;
            }
        }
        if let Some(src_port_filter) = config.filter.src_port_filter {
            if ctx.src_port != src_port_filter {
                return;
            }
        }
        if let Some(dst_port_filter) = config.filter.dst_port_filter {
            if ctx.dst_port != dst_port_filter {
                return;
            }
        }

        // ---- Exclude port list ----
        if !config.filter.exclude_ports.is_empty() {
            if config.filter.exclude_ports.contains(&ctx.src_port)
                || config.filter.exclude_ports.contains(&ctx.dst_port)
            {
                return;
            }
        }

        // ================================================================
        // END FILTERS Ã¢â‚¬â€ normal pipeline begins
        // ================================================================

        let flow_id = format!(
            "{}:{}-{}:{}-{}",
            ctx.src_ip, ctx.src_port,
            ctx.dst_ip, ctx.dst_port,
            ctx.protocol
        );

        // ---------------- FLOW ENGINE ----------------
        let flow_key = normalize_flow(
            ctx.src_ip, ctx.src_port,
            ctx.dst_ip, ctx.dst_port,
        );
        let is_new_flow = !flow_table.flows.contains_key(&flow_key);

        // Seed flow_packets before update so analyzers see correct packet count.
        if let Some(flow) = flow_table.flows.get(&flow_key) {
            ctx.flow_packets = flow.packets;
        }

        flow_table.update_flow_from_context(
            ctx,
            dns_cache,
            &analyzer_manager.rdns_cache,
            payload.len(),
            config,
        );

        // Refresh flow_packets with the incremented value post-update.
        if let Some(flow) = flow_table.flows.get(&flow_key) {
            ctx.flow_packets = flow.packets;
        }

        // ---------------- FLOW LIFECYCLE EVENTS ----------------
        if let Some(bus) = event_bus {
            let should_emit_flow = is_new_flow || !config.output.suppress_flow_updates;
            if should_emit_flow {
                if let Some(flow) = flow_table.flows.get(&flow_key) {
                    let event_type = if is_new_flow {
                        EventType::FlowNew
                    } else {
                        EventType::FlowUpdate
                    };
                    let mut event = SnfEvent::new(
                        0, self.packet_counter, ctx.timestamp_us,
                        event_type, ctx.protocol.clone(), flow_id.clone(),
                    );
                    event.attr_ip("src_ip", ctx.src_ip);
                    event.attr_u16("src_port", ctx.src_port);
                    event.attr_ip("dst_ip", ctx.dst_ip);
                    event.attr_u16("dst_port", ctx.dst_port);
                    event.attr_u64("packet_size", ctx.packet_size as u64);
                    if let Some(ref domain) = flow.domain {
                        event.attr_str("domain", domain.to_string());
                    }
                    event.attr_u64("flow_tx_bytes",  flow.bytes_sent);
                    event.attr_u64("flow_rx_bytes",  flow.bytes_received);
                    event.attr_u64("flow_packets",   flow.packets);
                    bus.emit(event);
                }
            }
        }

        // ---------------- TCP REASSEMBLY ----------------
        let analyzer_payload: Vec<u8>;
        let payload_ref: &[u8];

        if ctx.protocol == "TCP" {
            if let Some(seq) = tcp_seq {
                match self.tcp_reassembler.process_segment(
                    ctx.src_ip, ctx.src_port,
                    ctx.dst_ip, ctx.dst_port,
                    seq, payload, ctx.timestamp_us,
                ) {
                    ReassemblyResult::Assembled(data) => {
                        analyzer_payload = data;
                        payload_ref = &analyzer_payload;
                    }
                    ReassemblyResult::Buffered => {
                        self.run_periodic_cleanup(ctx.timestamp_us, flow_table);
                        return;
                    }
                    ReassemblyResult::Reset(reason) => {
                        self.emit_parse_error(
                            event_bus, self.packet_counter, ctx.timestamp_us,
                            "TCP", &reason, 0,
                        );
                        self.run_periodic_cleanup(ctx.timestamp_us, flow_table);
                        return;
                    }
                    ReassemblyResult::Passthrough => {
                        self.run_periodic_cleanup(ctx.timestamp_us, flow_table);
                        return;
                    }
                }
            } else {
                payload_ref = payload;
                analyzer_payload = Vec::new();
                let _ = &analyzer_payload;
            }
        } else {
            payload_ref = payload;
            analyzer_payload = Vec::new();
            let _ = &analyzer_payload;
        }

        // ---------------- RUN ANALYZERS ----------------
        if let Some(flow) = flow_table.flows.get_mut(&flow_key) {
            let parse_errors = analyzer_manager.run(
                ctx, payload_ref, flow, dns_cache, config,
            );

            if !config.output.suppress_parse_errors {
                for err in parse_errors {
                    self.emit_parse_error(
                        event_bus, self.packet_counter, ctx.timestamp_us,
                        err.protocol, &err.reason, err.offset,
                    );
                }
            }

            // ---- Domain filter (post-analysis, domain may now be resolved) ----
            if let Some(filter) = &config.domain_filter {
                match flow.domain.as_deref() {
                    Some(domain) if domain.contains(filter.as_str()) => {}
                    _ => {
                        self.run_periodic_cleanup(ctx.timestamp_us, flow_table);
                        return;
                    }
                }
            }
        }


        // ---------------- DNS ANSWER Ã¢â€ â€™ IP BINDING ----------------
        if config.protocol.enable_dns && ctx.dns_is_response {
            if let (Some(domain), Some(resolved_ip)) =
                (&ctx.dns_query_name, ctx.dns_resolved_ip)
            {
                dns_cache.insert(resolved_ip, domain.clone());

                if config.output.show_dns_logs {
                    println!("[DNS] Cached: {} Ã¢â€ â€™ {}", resolved_ip, domain);
                }
            }
            if let Some(ref ptr) = ctx.dns_ptr_record {
                dns_cache.insert(ctx.src_ip, ptr.clone());
            }

            // Phase 9F: DNS response received Ã¢â‚¬â€ rebind immediately so flows
            // waiting on this domain get attributed without delay.
            // This is the primary trigger; the background sweep below is a
            // safety net for edge cases (e.g. DoH where DNS bypasses this path).
            flow_table.rebind_domains(dns_cache, &analyzer_manager.rdns_cache);
        }

        // ---------------- DHCP LEASE Ã¢â€ â€™ DEVICE BINDING ----------------
        if config.protocol.enable_dhcp {
            if let Some(ref msg_type) = ctx.dhcp_msg_type.clone() {
                if msg_type == "ACK" || msg_type == "OFFER" {
                    if let Some(ref assigned_ip_str) = ctx.dhcp_assigned_ip.clone() {
                        if let Ok(assigned_ip) = IpAddr::from_str(assigned_ip_str) {
                            let label = ctx.dhcp_hostname
                                .as_deref()
                                .or(ctx.dhcp_client_mac.as_deref())
                                .unwrap_or("dhcp-device");
                            dns_cache.insert(assigned_ip, label.to_string());
                            if config.output.show_dhcp_logs {
                                println!(
                                    "[DHCP] Bound: {} Ã¢â€ â€™ {} ({})",
                                    assigned_ip, label, msg_type,
                                );
                            }
                        }
                    }
                }
            }
        }

        // ---------------- mDNS ANSWER Ã¢â€ â€™ DNS CACHE BINDING ----------------
        if config.protocol.enable_mdns && ctx.mdns_is_response {
            if let Some(ref mdns_name) = ctx.mdns_query_name.clone() {
                let record_type = ctx.mdns_record_type.as_deref().unwrap_or("");
                if record_type == "A" || record_type == "AAAA" {
                    dns_cache.insert(ctx.src_ip, mdns_name.clone());
                    if config.output.show_mdns_logs {
                        println!("[mDNS] Cached: {} Ã¢â€ â€™ {}", ctx.src_ip, mdns_name);
                    }
                }
            }
        }

        // ---------------- PROTOCOL EVENT EMISSION ----------------
        self.emit_protocol_events(ctx, config, &flow_id, event_bus);

        // ---------------- PHASE 9F: BACKGROUND REBIND SWEEP ----------------
        // Safety net for flows that gained domain info from non-DNS paths
        // (e.g. TLS SNI, HTTP Host) or when DNS was processed via DoH.
        // O(f) cost is acceptable Ã¢â‚¬â€ runs at most once every 1000 packets.
        if self.packet_counter % REBIND_INTERVAL_PACKETS == 0 {
            flow_table.rebind_domains(dns_cache, &analyzer_manager.rdns_cache);
        }

        // ---------------- SERVICE DETECTION ----------------
        let mut service = ports::get_service(ctx.src_port, ports_db);
        if service == "UNKNOWN" {
            service = ports::get_service(ctx.dst_port, ports_db);
        }

        // ---------------- PACKET LOGGING ----------------
       // ---------------- PACKET LOGGING ----------------
        if config.output.show_packet_logs {
            println!("Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬");
            println!("Client: {}:{}", ctx.src_ip, ctx.src_port);
            println!("Server: {}:{}", ctx.dst_ip, ctx.dst_port);
            println!("Service: {}", service);
            if let Some(domain) = &ctx.dns_domain {
                println!("Domain: {}", domain);
            }
            println!("Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬");
        }

        // ---------------- PERIODIC CLEANUP ----------------
        self.run_periodic_cleanup(ctx.timestamp_us, flow_table);

        // ---------------- FLOW COUNT ----------------
        if config.output.show_flow_logs {
            println!(
                "Active flows: {} | TCP streams: {}",
                flow_table.flow_count(),
                self.tcp_reassembler.stream_count(),
            );
        }
    }

    // ----------------------------------------------------------------
    // PROTOCOL EVENT EMISSION (preserved from Phase 5 / Reliability Pass)
    // ----------------------------------------------------------------
    fn emit_protocol_events(
        &self,
        ctx: &PacketContext,
        config: &EngineConfig,
        flow_id: &str,
        event_bus: &mut Option<EventBus>,
    ) {
        let bus = match event_bus {
            Some(b) => b,
            None => return,
        };

        let pid = self.packet_counter;
        let ts  = ctx.timestamp_us;

        // ---- DNS ----
        if config.protocol.enable_dns {
            if let Some(ref query_name) = ctx.dns_query_name {
                let event_type = if ctx.dns_is_response {
                    EventType::DnsResponse
                } else {
                    EventType::DnsQuery
                };
                let mut e = SnfEvent::new(0, pid, ts, event_type, "DNS", flow_id);
                e.attr_str("query_name", query_name.clone());
                e.attr_bool("is_response", ctx.dns_is_response);
                if let Some(ref rtype) = ctx.dns_record_type  { e.attr_str("record_type", rtype.clone()); }
                if let Some(ttl)       = ctx.dns_ttl           { e.attr_u64("ttl", ttl as u64); }
                if let Some(resolved)  = ctx.dns_resolved_ip   { e.attr_ip("resolved_ip", resolved); }
                if let Some(ref ptr)   = ctx.dns_ptr_record    { e.attr_str("ptr_record", ptr.clone()); }
                if !ctx.dns_cname_chain.is_empty() { e.attr_str_list("cname_chain",  ctx.dns_cname_chain.clone()); }
                if !ctx.dns_mx_records.is_empty()  { e.attr_str_list("mx_records",   ctx.dns_mx_records.clone()); }
                if !ctx.dns_ns_records.is_empty()  { e.attr_str_list("ns_records",   ctx.dns_ns_records.clone()); }
                if !ctx.dns_txt_records.is_empty() { e.attr_str_list("txt_records",  ctx.dns_txt_records.clone()); }
                if !ctx.dns_srv_records.is_empty() { e.attr_str_list("srv_records",  ctx.dns_srv_records.clone()); }
                bus.emit(e);

                if config.output.show_dns_logs {
                    println!(
                        "[DNS] {} {} type={} ttl={:?} resolved={:?}",
                        if ctx.dns_is_response { "response" } else { "query" },
                        query_name,
                        ctx.dns_record_type.as_deref().unwrap_or("?"),
                        ctx.dns_ttl,
                        ctx.dns_resolved_ip,
                    );
                }
            }
        }

        // ---- TLS CLIENT HELLO ----
        if config.protocol.enable_tls {
            if let Some(ref sni) = ctx.tls_sni {
                let mut e = SnfEvent::new(0, pid, ts, EventType::TlsClientHello, "TLS", flow_id);
                e.attr_str("sni", sni.clone());
                e.attr_bool("session_resumed", ctx.tls_session_resumed);
                if let Some(ref ver)  = ctx.tls_version       { e.attr_str("tls_version", ver.clone()); }
                if let Some(ref alpn) = ctx.tls_alpn           { e.attr_str("alpn", alpn.clone()); }
                if let Some(ref ja3)  = ctx.ja3_hash           { e.attr_str("ja3", ja3.clone()); }
                if let Some(ref ja4)  = ctx.ja4_hash           { e.attr_str("ja4", ja4.clone()); }
                if let Some(ref ja4)  = ctx.ja4_hash        { e.attr_str("ja4", ja4.clone()); }
                if let Some(ref fp)   = ctx.ja3_fingerprint  { e.attr_str("ja3_label", fp.clone()); }   
                if let Some(ref fp)   = ctx.ja4_fingerprint  { e.attr_str("ja4_label", fp.clone()); }   
                if let Some(ref fp)   = ctx.ja3_fingerprint    { e.attr_str("ja3_label", fp.clone()); }
                if !ctx.tls_alpn_protocols.is_empty()  { e.attr_str_list("alpn_protocols", ctx.tls_alpn_protocols.clone()); }
                if !ctx.tls_cipher_suites.is_empty()   { e.attr_u16_list("cipher_suites",  ctx.tls_cipher_suites.clone()); }
                if let Some(ref cn)     = ctx.tls_cert_cn      { e.attr_str("cert_cn", cn.clone()); }
                if !ctx.tls_cert_sans.is_empty()               { e.attr_str_list("cert_sans", ctx.tls_cert_sans.clone()); }
                if let Some(ref issuer) = ctx.tls_cert_issuer  { e.attr_str("cert_issuer", issuer.clone()); }
                if let Some(ref exp)    = ctx.tls_cert_not_after { e.attr_str("cert_not_after", exp.clone()); }
                bus.emit(e);

                if config.output.show_tls_logs {
                    println!(
                        "[TLS] ClientHello sni={} alpn={} version={} resumed={}",
                        sni,
                        ctx.tls_alpn.as_deref().unwrap_or("none"),
                        ctx.tls_version.as_deref().unwrap_or("?"),
                        ctx.tls_session_resumed,
                    );
                }
            }

            // ---- TLS SERVER HELLO ----
            if ctx.tls_sni.is_none() && !ctx.tls_cipher_suites.is_empty() {
                let mut e = SnfEvent::new(0, pid, ts, EventType::TlsServerHello, "TLS", flow_id);
                e.attr_u16_list("cipher_suites", ctx.tls_cipher_suites.clone());
                if let Some(ref ver)  = ctx.tls_version  { e.attr_str("tls_version", ver.clone()); }
                if let Some(ref alpn) = ctx.tls_alpn      { e.attr_str("alpn", alpn.clone()); }
                if let Some(ref ja3s) = ctx.ja3s_hash        { e.attr_str("ja3s", ja3s.clone()); }
                if let Some(ref fp)   = ctx.ja3s_fingerprint { e.attr_str("ja3s_label", fp.clone()); }
                bus.emit(e);
            }
        }

        // ---- HTTP REQUEST ----
        if config.protocol.enable_http {
            if let Some(ref method) = ctx.http_method {
                let mut e = SnfEvent::new(0, pid, ts, EventType::HttpRequest, "HTTP", flow_id);
                e.attr_str("method", method.clone());
                if let Some(ref uri)  = ctx.http_uri            { e.attr_str("uri", uri.clone()); }
                if let Some(ref ver)  = ctx.http_version        { e.attr_str("http_version", ver.clone()); }
                if let Some(ref host) = ctx.http_host           { e.attr_str("host", host.clone()); }
                if let Some(ref ua)   = ctx.http_user_agent     { e.attr_str("user_agent", ua.clone()); }
                if let Some(ref ct)   = ctx.http_content_type   { e.attr_str("content_type", ct.clone()); }
                if let Some(cl)       = ctx.http_content_length { e.attr_u64("content_length", cl); }
                bus.emit(e);

                if config.output.show_http_logs {
                    println!(
                        "[HTTP] {} {} host={}",
                        method,
                        ctx.http_uri.as_deref().unwrap_or("/"),
                        ctx.http_host.as_deref().unwrap_or(""),
                    );
                }
            }

            if let Some(status) = ctx.http_status_code {
                let mut e = SnfEvent::new(0, pid, ts, EventType::HttpResponse, "HTTP", flow_id);
                e.attr_u16("status_code", status);
                if let Some(ref ver) = ctx.http_version        { e.attr_str("http_version", ver.clone()); }
                if let Some(ref ct)  = ctx.http_content_type   { e.attr_str("content_type", ct.clone()); }
                if let Some(cl)      = ctx.http_content_length { e.attr_u64("content_length", cl); }
                bus.emit(e);
            }
        }

        // ---- QUIC ----
        if config.protocol.enable_quic {
            let has_quic_data = ctx.tls_sni.is_some() || ctx.quic_version.is_some();
            let on_quic_port  = config.protocol.quic_ports.contains(&ctx.src_port)
                             || config.protocol.quic_ports.contains(&ctx.dst_port);
            if has_quic_data && on_quic_port {
                let mut e = SnfEvent::new(0, pid, ts, EventType::QuicSni, "QUIC", flow_id);
                if let Some(ref sni) = ctx.tls_sni       { e.attr_str("sni", sni.clone()); }
                if let Some(ref ver) = ctx.quic_version  { e.attr_str("quic_version", ver.clone()); }
                if let Some(ref ja4) = ctx.ja4_hash      { e.attr_str("ja4", ja4.clone()); }
                bus.emit(e);
            }
        }

        // ---- DHCP ----
        if config.protocol.enable_dhcp {
            if let Some(ref msg_type) = ctx.dhcp_msg_type {
                let mut e = SnfEvent::new(0, pid, ts, EventType::DhcpMessage, "DHCP", flow_id);
                e.attr_str("msg_type", msg_type.clone());
                if let Some(ref mac)    = ctx.dhcp_client_mac   { e.attr_str("client_mac",   mac.clone()); }
                if let Some(ref host)   = ctx.dhcp_hostname      { e.attr_str("hostname",     host.clone()); }
                if let Some(ref ip)     = ctx.dhcp_assigned_ip   { e.attr_str("assigned_ip",  ip.clone()); }
                if let Some(ref ip)     = ctx.dhcp_requested_ip  { e.attr_str("requested_ip", ip.clone()); }
                if let Some(ref vendor) = ctx.dhcp_vendor_class  { e.attr_str("vendor_class", vendor.clone()); }
                bus.emit(e);

                if config.output.show_dhcp_logs {
                    println!(
                        "[DHCP] {} mac={} hostname={} ip={}",
                        msg_type,
                        ctx.dhcp_client_mac.as_deref().unwrap_or("?"),
                        ctx.dhcp_hostname.as_deref().unwrap_or(""),
                        ctx.dhcp_assigned_ip.as_deref()
                            .or(ctx.dhcp_requested_ip.as_deref())
                            .unwrap_or(""),
                    );
                }
            }
        }

        // ---- ICMP ----
        if config.protocol.enable_icmp {
            if let Some(icmp_type) = ctx.icmp_type {
                let mut e = SnfEvent::new(0, pid, ts, EventType::IcmpMessage, "ICMP", flow_id);
                e.attr_u8("icmp_type", icmp_type);
                e.attr_ip("src_ip", ctx.src_ip);
                e.attr_ip("dst_ip", ctx.dst_ip);
                if let Some(code)     = ctx.icmp_code         { e.attr_u8("icmp_code", code); }
                if let Some(ref desc) = ctx.icmp_description  { e.attr_str("description", desc.clone()); }
                bus.emit(e);
            }
        }

        // ---- SMB ----
        if config.protocol.enable_smb {
            if let Some(ref command) = ctx.smb_command {
                let mut e = SnfEvent::new(0, pid, ts, EventType::SmbSession, "SMB", flow_id);
                e.attr_str("command", command.clone());
                e.attr_ip("src_ip", ctx.src_ip);
                e.attr_ip("dst_ip", ctx.dst_ip);
                if let Some(ref ver)    = ctx.smb_version { e.attr_str("smb_version", ver.clone()); }
                if let Some(ref status) = ctx.smb_status  { e.attr_str("status",      status.clone()); }
                bus.emit(e);
            }
        }

        // ---- mDNS ----
        if config.protocol.enable_mdns {
            if let Some(ref query_name) = ctx.mdns_query_name {
                let mut e = SnfEvent::new(0, pid, ts, EventType::MdnsRecord, "mDNS", flow_id);
                e.attr_str("query_name", query_name.clone());
                e.attr_bool("is_response", ctx.mdns_is_response);
                e.attr_ip("src_ip", ctx.src_ip);
                if let Some(ref rtype) = ctx.mdns_record_type { e.attr_str("record_type", rtype.clone()); }
                bus.emit(e);
            }
        }

        // ---- ICS / SCADA — Phase 18 ----
        if config.protocol.enable_ics {
            if let Some(ref ics_proto) = ctx.ics_protocol {
                let (event_type, proto_str) = match ics_proto.as_str() {
                    "Modbus"      => (EventType::IcsModbus,     "MODBUS"),
                    "DNP3"        => (EventType::IcsDnp3,       "DNP3"),
                    "S7comm"      => (EventType::IcsS7comm,     "S7COMM"),
                    "EtherNet/IP" => (EventType::IcsEtherNetIp, "ENIP"),
                    "PROFINET"    => (EventType::IcsProfinet,   "PROFINET"),
                    _             => (EventType::IcsModbus,     "ICS"),
                };
                let mut e = SnfEvent::new(0, pid, ts, event_type, proto_str, flow_id);
                e.attr_str("ics_protocol", ics_proto.clone());
                e.attr_ip("src_ip", ctx.src_ip);
                e.attr_ip("dst_ip", ctx.dst_ip);
                e.attr_u16("dst_port", ctx.dst_port);

                // Modbus attributes
                if let Some(ref fc) = ctx.modbus_function_code { e.attr_str("function_code", fc.clone()); }
                if let Some(uid)    = ctx.modbus_unit_id        { e.attr_u8("unit_id", uid); }
                if ctx.modbus_exception                          { e.attr_bool("exception", true); }
                if let Some(addr)   = ctx.modbus_register_addr  { e.attr_u16("register_addr", addr); }
                if let Some(cnt)    = ctx.modbus_register_count { e.attr_u16("register_count", cnt); }

                // DNP3 attributes
                if let Some(ref fc)  = ctx.dnp3_function_code { e.attr_str("function_code", fc.clone()); }
                if let Some(ref iin) = ctx.dnp3_iin_flags      { e.attr_str("iin_flags", iin.clone()); }
                if !ctx.dnp3_objects.is_empty() { e.attr_str_list("dnp3_objects", ctx.dnp3_objects.clone()); }

                // S7comm attributes
                if let Some(ref pdu) = ctx.s7_pdu_type  { e.attr_str("pdu_type", pdu.clone()); }
                if let Some(ref fc)  = ctx.s7_function   { e.attr_str("function_code", fc.clone()); }
                if let Some(dlen)    = ctx.s7_data_len   { e.attr_u16("data_len", dlen); }

                // EtherNet/IP + CIP attributes
                if let Some(ref cmd) = ctx.enip_command        { e.attr_str("enip_command", cmd.clone()); }
                if let Some(sess)    = ctx.enip_session_handle { e.attr_u64("session_handle", sess as u64); }
                if let Some(ref svc) = ctx.cip_service         { e.attr_str("cip_service", svc.clone()); }
                if let Some(cls)     = ctx.cip_class           { e.attr_u16("cip_class", cls); }
                if let Some(inst)    = ctx.cip_instance        { e.attr_u16("cip_instance", inst); }
                if let Some(ref st)  = ctx.cip_status          { e.attr_str("cip_status", st.clone()); }

                // PROFINET attributes
                if let Some(fid)    = ctx.profinet_frame_id        { e.attr_u16("frame_id", fid); }
                if let Some(ref sv) = ctx.profinet_service          { e.attr_str("service", sv.clone()); }
                if let Some(ref sn) = ctx.profinet_station_name     { e.attr_str("station_name", sn.clone()); }
                if let Some(ref ip) = ctx.profinet_ip_addr          { e.attr_str("ip_addr", ip.clone()); }
                if let Some(ref mac)= ctx.profinet_mac              { e.attr_str("mac", mac.clone()); }

                bus.emit(e);

                if config.output.show_packet_logs {
                    println!("[ICS] proto={} fc={:?} src={}:{}",
                        ics_proto,
                        ctx.modbus_function_code.as_deref()
                            .or(ctx.dnp3_function_code.as_deref())
                            .or(ctx.s7_function.as_deref())
                            .or(ctx.enip_command.as_deref()),
                        ctx.src_ip, ctx.src_port
                    );
                }
            }
        }

        // ---- LAN DISCOVERY (LLDP / CDP) — Phase 18 ----
        if config.protocol.enable_lan {
            // LLDP
            if ctx.lldp_chassis_id.is_some() || ctx.lldp_system_name.is_some() {
                let mut e = SnfEvent::new(0, pid, ts, EventType::LanLldp, "LLDP", flow_id);
                e.attr_ip("src_ip", ctx.src_ip);
                if let Some(ref c) = ctx.lldp_chassis_id   { e.attr_str("chassis_id",   c.clone()); }
                if let Some(ref p) = ctx.lldp_port_id      { e.attr_str("port_id",      p.clone()); }
                if let Some(ttl)   = ctx.lldp_ttl           { e.attr_u16("ttl",          ttl); }
                if let Some(ref n) = ctx.lldp_system_name  { e.attr_str("system_name",  n.clone()); }
                if let Some(ref d) = ctx.lldp_system_desc  { e.attr_str("system_desc",  d.clone()); }
                if let Some(ref pd)= ctx.lldp_port_desc    { e.attr_str("port_desc",    pd.clone()); }
                if let Some(ref m) = ctx.lldp_mgmt_addr    { e.attr_str("mgmt_addr",    m.clone()); }
                if let Some(ref c) = ctx.lldp_capabilities { e.attr_str("capabilities", c.clone()); }
                if let Some(vlan)  = ctx.lldp_vlan_id      { e.attr_u16("vlan_id",      vlan); }
                bus.emit(e);

                if config.output.show_packet_logs {
                    println!("[LLDP] chassis={:?} sysname={:?} mgmt={:?}",
                        ctx.lldp_chassis_id, ctx.lldp_system_name, ctx.lldp_mgmt_addr);
                }
            }

            // CDP
            if ctx.cdp_device_id.is_some() || ctx.cdp_platform.is_some() {
                let mut e = SnfEvent::new(0, pid, ts, EventType::LanCdp, "CDP", flow_id);
                e.attr_ip("src_ip", ctx.src_ip);
                if let Some(ref d) = ctx.cdp_device_id   { e.attr_str("device_id",   d.clone()); }
                if let Some(ref p) = ctx.cdp_port_id     { e.attr_str("port_id",     p.clone()); }
                if let Some(ref pl)= ctx.cdp_platform    { e.attr_str("platform",    pl.clone()); }
                if let Some(ref c) = ctx.cdp_capabilities{ e.attr_str("capabilities",c.clone()); }
                if let Some(ref vt)= ctx.cdp_vtp_domain  { e.attr_str("vtp_domain",  vt.clone()); }
                if let Some(vlan)  = ctx.cdp_native_vlan { e.attr_u16("native_vlan", vlan); }
                if !ctx.cdp_addresses.is_empty() { e.attr_str_list("addresses", ctx.cdp_addresses.clone()); }
                bus.emit(e);

                if config.output.show_packet_logs {
                    println!("[CDP] device_id={:?} platform={:?} vlan={:?}",
                        ctx.cdp_device_id, ctx.cdp_platform, ctx.cdp_native_vlan);
                }
            }
        }
    }

    fn emit_parse_error(
        &self,
        event_bus: &mut Option<EventBus>,
        packet_id: u64,
        timestamp_us: u64,
        protocol: &str,
        reason: &str,
        offset: usize,
    ) {
        if let Some(bus) = event_bus {
            let mut event = SnfEvent::new(
                0, packet_id, timestamp_us,
                EventType::ParseError, protocol, "",
            );
            event.attr_str("reason", reason.to_string());
            if offset > 0 {
                event.attr_u64("offset", offset as u64);
            }
            bus.emit(event);
        }
    }

    fn run_periodic_cleanup(&mut self, now_us: u64, flow_table: &mut FlowTable) {
        if self.packet_counter % EXPIRE_INTERVAL_PACKETS == 0 {
            flow_table.expire_flows(now_us, FLOW_IDLE_TIMEOUT_US);
            self.tcp_reassembler.evict_idle_streams(now_us);
        }
    }
}

// ----------------------------------------------------------------
// FILTER HELPER FUNCTIONS
// ----------------------------------------------------------------

/// Returns true if the IP is a loopback address (127.x.x.x or ::1).
#[inline]
fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Returns true if the IP is a multicast address (224.0.0.0/4 or ff00::/8).
#[inline]
fn is_multicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// Returns true if the IP is the IPv4 limited broadcast (255.255.255.255).
/// Subnet-directed broadcast requires local subnet knowledge Ã¢â‚¬â€ not available here.
#[inline]
fn is_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_broadcast(),
        IpAddr::V6(_)  => false,
    }
}
