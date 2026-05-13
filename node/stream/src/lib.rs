#[macro_use]
extern crate tracing;

mod config;
mod stream_manager;

pub use config::Config as StreamConfig;
pub use stream_manager::{merge_persisted_streams, StreamManager};
