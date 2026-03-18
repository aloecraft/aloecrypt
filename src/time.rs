use std::time::Duration;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod system_time {
    pub use instant::SystemTime;
    pub const UNIX_EPOCH: SystemTime = SystemTime::UNIX_EPOCH;
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod system_time {
    pub use std::time::{SystemTime, UNIX_EPOCH};
}

pub use system_time::{SystemTime, UNIX_EPOCH};
