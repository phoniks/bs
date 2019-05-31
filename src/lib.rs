#![feature(try_trait)]
#![feature(try_from)]

pub use self::error::{Error, Result};
pub mod error;

pub use self::identity::*;
pub mod identity;

pub use self::sign::*;
pub mod sign;

pub use self::verify::*;
pub mod verify;

pub use self::fs::*;
pub mod fs;
