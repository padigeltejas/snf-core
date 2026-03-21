use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub ip1: IpAddr,
    pub port1: u16,
    pub ip2: IpAddr,
    pub port2: u16,
}

pub fn normalize_flow(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> FlowKey {

    if (src_ip, src_port) <= (dst_ip, dst_port) {
        FlowKey {
            ip1: src_ip,
            port1: src_port,
            ip2: dst_ip,
            port2: dst_port,
        }
    } else {
        FlowKey {
            ip1: dst_ip,
            port1: dst_port,
            ip2: src_ip,
            port2: src_port,
        }
    }
}