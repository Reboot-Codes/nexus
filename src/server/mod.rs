pub mod listener;
pub mod models;
pub mod websockets;

// TODO: Move all events to ones with data that has a set serde model!

pub const DEAUTH_EVENT: &str = "nexus://com.reboot-codes.nexus/websockets/deauthorize";
pub const AUTH_HEADER: &str = "Authorization";
pub const MAX_SIZE: usize = 8388608;
