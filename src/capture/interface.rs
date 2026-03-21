use pcap::{Device, Capture};
use std::time::{Duration, Instant};

/// Auto-detect the most active capture interface
pub fn auto_detect_interface(devices: &[Device]) -> Option<Device> {

    for device in devices {

        let name = device.name.to_lowercase();

        // Skip useless adapters
        if name.contains("loopback")
            || name.contains("wan")
            || name.contains("npcap")
        {
            continue;
        }

        println!("Testing interface: {}", device.name);

        let mut cap = match Capture::from_device(device.clone()) {
            Ok(c) => match c.promisc(true).timeout(200).open() {
                Ok(cap) => cap,
                Err(_) => continue,
            },
            Err(_) => continue,
        };

        let start = Instant::now();
        let mut packets = 0;

        while start.elapsed() < Duration::from_millis(500) {
            if cap.next_packet().is_ok() {
                packets += 1;
                break;
            }
        }

        if packets > 0 {
            println!("Active interface detected: {}", device.name);
            return Some(device.clone());
        }
    }

    None
}