use crate::Result;
use std::path::PathBuf;

pub fn verify(_verbose: bool,
              _status_fd: &Option<u32>, 
              _manifest: &PathBuf) -> Result<()> {
    Ok(())
}
