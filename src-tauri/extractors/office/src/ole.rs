//! Thin helpers over the `cfb` compound file crate.

use cfb::CompoundFile;
use extractor_core::Error;
use std::io::Read;

pub fn has_stream(file: &mut CompoundFile<std::fs::File>, path: &str) -> bool {
    file.open_stream(path).is_ok()
}

pub fn read_stream(file: &mut CompoundFile<std::fs::File>, path: &str) -> Result<Vec<u8>, Error> {
    let mut stream = file
        .open_stream(path)
        .map_err(|e| Error::Extract(format!("cannot open stream {path}: {e}")))?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(Error::Io)?;
    Ok(buf)
}

/// Bounds-checked little-endian cursor over a byte slice.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.pos + n > self.data.len() {
            return Err(Error::Extract("unexpected end of stream".into()));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<(), Error> {
        self.take(n).map(|_| ())
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}
