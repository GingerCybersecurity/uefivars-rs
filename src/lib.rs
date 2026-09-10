//! UEFI variable store library.
//!
//! Read, write, and manipulate UEFI variable stores in multiple formats
//! (AWS, EDK2/OVMF, JSON). Ported from
//! [python-uefivars](https://github.com/awslabs/python-uefivars).

mod error;
mod var;

pub mod aws;
pub mod edk2;
pub mod json;
pub mod secboot;

pub use error::{Error, Result};
pub use var::{attr, guid, EphemeralReport, UefiVar, UefiVarStore};
