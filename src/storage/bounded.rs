//! Bounded reads inspect the bytes from one regular handle, never metadata alone.
use crate::platform::file_transaction::{self as native, Identity};
use crate::{AppError, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub(super) fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    Ok(read_identified(path, limit)?.0)
}
pub(super) fn read_identified(path: &Path, limit: u64) -> Result<(Vec<u8>, Identity)> {
    let mut file = native::open_regular(path, false).map_err(|e| AppError::io(path, e))?;
    let id = native::identity(&file, true).map_err(|e| AppError::io(path, e))?;
    let len = file.metadata().map_err(|e| AppError::io(path, e))?.len();
    if len > limit {
        return Err(AppError::InvalidVault("file exceeds size limit"));
    }
    let bytes = read_limit(&mut file, limit).map_err(|e| AppError::io(path, e))?;
    if bytes.len() as u64 != len || file.metadata().map_err(|e| AppError::io(path, e))?.len() != len
    {
        return Err(AppError::InvalidVault("file size changed during read"));
    }
    Ok((bytes, id))
}
fn read_limit(reader: impl Read, limit: u64) -> std::io::Result<Vec<u8>> {
    let max = usize::try_from(
        limit
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("limit overflow"))?,
    )
    .map_err(|_| std::io::Error::other("limit overflow"))?;
    let mut bytes = Vec::new();
    let mut read = reader.take(max as u64);
    let mut chunk = [0; 8192];
    loop {
        let available = (max - bytes.len()).min(chunk.len());
        if available == 0 {
            return Err(std::io::Error::other("file exceeds size limit"));
        }
        let count = match read.read(&mut chunk[..available]) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            value => value?,
        };
        if count == 0 {
            break;
        }
        // reserve_exact avoids geometric capacity growth above limit+1.
        bytes.reserve_exact(count);
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}
pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| AppError::io(path, e))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| AppError::io(path, e))?;
    if read(path, bytes.len() as u64)? != bytes {
        return Err(AppError::InvalidVault("staged bytes differ"));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn small_limit_stops_growing_reader_at_limit_plus_one() {
        let mut input = std::io::Cursor::new(vec![7; 100]);
        assert!(read_limit(&mut input, 8).is_err());
        assert_eq!(input.position(), 9);
        assert_eq!(read_limit(&b"eight!!!"[..], 8).unwrap(), b"eight!!!");
    }
}
