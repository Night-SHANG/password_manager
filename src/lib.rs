#![deny(unsafe_code)]

pub mod app;
pub mod domain;
pub mod error;
pub mod export;
pub mod import;
mod operations;
pub mod platform;
pub mod preferences;
pub mod security;
pub mod services;
pub mod smoke;
pub mod storage;

pub use error::{AppError, Result};
