use pcap::Device;

#[derive(Clone)]
pub enum Source {
    Port(u16),
    Filename(String),
    Device(Device), // device name used to filter devices
}

#[cfg(windows)]
pub mod windows;

#[cfg(not(windows))]
pub mod unix;