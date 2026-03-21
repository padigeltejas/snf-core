#[derive(Clone)]
pub struct DeviceConfig {
    pub enable_device_discovery: bool,
    pub device_tracking_limit: usize,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            enable_device_discovery: true,
            device_tracking_limit: 1000,
        }
    }
}
