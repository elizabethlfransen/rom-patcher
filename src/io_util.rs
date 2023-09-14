use std::fs::File;
use std::io::{Cursor, Read, Result as IOResult};
use crate::Error;
use crate::ErrorKind::ParsingError;

pub trait U32Extensions {
    fn to_u24_be_bytes(&self) -> [u8; 3];
    fn from_u24_be_bytes(bytes: &[u8]) -> Self;
}

impl U32Extensions for u32 {
    fn to_u24_be_bytes(&self) -> [u8; 3] {
        return [
            ((*self >> 16) & 0xFF) as u8,
            ((*self >> 8) & 0xFF) as u8,
            ((*self) & 0xFF) as u8,
        ];
    }

    fn from_u24_be_bytes(bytes: &[u8]) -> Self {
        return (bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32;
    }
}

pub trait ReaderExtensions {
    fn read_u24_be(&mut self, err_message: String) -> Result<u32,Error>;
    fn read_u16_be(&mut self, err_message: String) -> Result<u16,Error>;

    fn read_u8(&mut self, err_message: String) -> Result<u8, Error>;
}

impl<T> ReaderExtensions for T where T : Read {
    fn read_u24_be(&mut self, err_message: String) -> Result<u32,Error> {
        {
            let mut buf: [u8;3] = [0;3];
            self.read_exact(&mut buf).map_err(|e| Error::new(ParsingError)
                .with_description(err_message)
                .with_source(Box::new(e))
            )?;
            return Ok(u32::from_u24_be_bytes(&buf));
        }
    }

    fn read_u16_be(&mut self, err_message: String) -> Result<u16, Error> {
        let mut buf: [u8;2] = [0;2];
        self.read_exact(&mut buf).map_err(|e|Error::new(ParsingError)
            .with_description(err_message)
            .with_source(Box::new(e))
        )?;
        return Ok(u16::from_be_bytes(buf));
    }

    fn read_u8(&mut self, err_message: String) -> Result<u8, Error> {
        let mut buf: [u8;1] = [0];
        self.read_exact(&mut buf).map_err(|e|Error::new(ParsingError)
            .with_description(err_message)
            .with_source(Box::new(e))
        )?;
        return Ok(buf[0]);
    }
}

pub trait AssertRead {
    fn assert_read(&mut self, expected: &[u8], read_error_message: String, parse_error_message: String) -> Result<(), Error>;
}

impl<T> AssertRead for T where T: Read {
    fn assert_read(&mut self, expected: &[u8], read_error_message: String, parse_error_message: String) -> Result<(), Error> {
        let mut buf = vec![0;expected.len()];

        self.read_exact(buf.as_mut())
            .map_err(|_| Error::new(ParsingError).with_description(read_error_message))?;
        if buf != expected {
            return Err(Error::new(ParsingError).with_description(parse_error_message));
        }
        Ok(())
    }
}


pub trait Truncate {
    fn truncate(&mut self, amount: u32) -> IOResult<()>;
}

impl Truncate for Vec<u8> {
    fn truncate(&mut self, amount: u32) -> IOResult<()> {
        self.truncate(amount as usize);
        Ok(())
    }
}

impl Truncate for File {
    fn truncate(&mut self, amount: u32) -> IOResult<()> {
        self.set_len(self.metadata().unwrap().len().min(amount as u64))
    }
}

impl <T> Truncate for Cursor<T> where T : Truncate {
    fn truncate(&mut self, amount: u32) -> IOResult<()> {
        self.get_mut().truncate(amount)?;
        Ok(())
    }
}