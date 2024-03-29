use std::io::{ErrorKind, Read, Result as IOResult, Seek, SeekFrom};
use std::io::Write;

use crate::Error;
use crate::ErrorKind::{ParsingError, PatchingError};
use crate::io_util::{AssertRead, ReaderExtensions, Truncate, U32Extensions};

/// Represents a regular hunk.
///
/// Regular hunks consist of a three-byte offset followed by a two-byte length of the payload and
/// the payload itself. Applying the hunk is done by writing the payload at the specified offset.
#[derive(Debug, PartialEq)]
pub struct IPSRegularHunkData {
    /// The offset to apply the payload.
    pub offset: u32,
    /// The length of the payload.
    pub length: u16,
    /// The payload to apply.
    pub payload: Box<[u8]>,
}


impl IPSRegularHunkData {
    /// writes `self` to `writer`.
    fn write(&self, writer: &mut impl Write) -> IOResult<()> {
        writer.write_all(&self.offset.to_u24_be_bytes())?;
        writer.write_all(&self.length.to_be_bytes())?;
        writer.write_all(&*self.payload)?;
        Ok(())
    }

    /// reads an [IPSHunk::Regular] from `reader` and adds it to `result`. Already parsed information must be passed to `offset`, `length`.
    fn read(reader: &mut impl Read, offset: u32, length: u16) -> Result<IPSHunk, Error> {
        let mut payload = vec![0; length as usize];
        reader.read_exact(&mut payload).map_err(|_| Error::new(ParsingError).with_description("Unable to read payload.".to_string()))?;
        Ok(IPSHunk::Regular(IPSRegularHunkData {
            offset,
            length,
            payload: payload.into_boxed_slice(),
        }))
    }

    /// Applies patch to `target`.
    fn apply<T>(&self, target: &mut T) -> Result<(), Error> where T: Seek + Write {
        target.seek(SeekFrom::Start(self.offset as u64))
            .map_err(|_| Error::new(PatchingError).with_description("Unable to apply ips regular hunk.".to_string()))?;
        target.write_all(self.payload.as_ref())
            .map_err(|_| Error::new(PatchingError).with_description("Unable to apply ips regular hunk.".to_string()))?;
        Ok(())
    }
}


/// Represents RLEHunk data.
///
/// RLE hunks have their length field set to zero; in place of a payload there is a two-byte length
/// of the run followed by a single byte indicating the value to be written. Applying the RLE hunk
/// is done by writing this byte the specified number of times at the specified offset.
#[derive(Debug, PartialEq)]
pub struct IPSRLEHunkData {
    /// the offset to write payload
    pub offset: u32,
    /// amount of times to write payload.
    pub run_length: u16,
    /// byte to repeat run_length times.
    pub payload: u8,
}

impl IPSRLEHunkData {
    /// writes `self` to `writer`.
    fn write(&self, writer: &mut impl Write) -> IOResult<()> {
        writer.write_all(&self.offset.to_u24_be_bytes())?;
        writer.write_all(&[0x0, 0x0])?; // rle hunks have length set to 0
        writer.write_all(&self.run_length.to_be_bytes())?;
        writer.write_all(&[self.payload])?;
        Ok(())
    }
    /// reads an [IPSHunk::RLE] from `reader` and adds it to `result`. Already parsed information must be passed to `offset`.
    fn read(reader: &mut impl Read, offset: u32) -> Result<IPSHunk, Error> {
        let run_length = reader.read_u16_be("Unable to read RLE run length.".to_string())?;
        let payload = reader.read_u8("Unable to read RLE payload.".to_string())?;
        return Ok(IPSHunk::RLE(IPSRLEHunkData {
            offset,
            run_length,
            payload,
        }));
    }

    /// Applies patch to `target`.
    fn apply<T>(&self, target: &mut T) -> Result<(), Error> where T: Seek + Write {
        // go to the offset
        target.seek(SeekFrom::Start(self.offset as u64))
            .map_err(|_| Error::new(PatchingError).with_description("Unable to apply ips RLE hunk.".to_string()))?;

        // write the payload
        target.write_all(vec![self.payload; self.run_length as usize].as_slice())
            .map_err(|_| Error::new(PatchingError).with_description("Unable to apply ips RLE hunk.".to_string()))?;
        Ok(())
    }
}

/// represents an IPS Hunk.
#[derive(Debug, PartialEq)]
pub enum IPSHunk {
    /// A [regular IPS hunk.](IPSRegularHunkData).
    Regular(IPSRegularHunkData),
    /// An [RLE IPS hunk.](IPSRLEHunkData).
    RLE(IPSRLEHunkData),
}

enum ReadHunkResult {
    Hunk(IPSHunk),
    EOF(Option<u32>),
}

impl IPSHunk {
    /// Reads optional truncate from `reader`. Truncate amount is set in `result`.
    fn read_trunc(reader: &mut impl Read) -> Result<ReadHunkResult, Error> {
        let mut trunc_buf = [0; 3];

        match reader.read_exact(&mut trunc_buf) {
            // write truncate amount if read
            Ok(_) =>
                Ok(ReadHunkResult::EOF(Some(u32::from_u24_be_bytes(&trunc_buf)))),

            // throw error if an error was received that isn't EOF
            Err(e) if e.kind() != ErrorKind::UnexpectedEof =>
                Err(Error::new(ParsingError).with_description("Unable to read truncate.".to_string())),

            _ => Ok(ReadHunkResult::EOF(None))
        }
    }

    /// checks if `offset` is [IPSPatch::EOF] and tries to read truncate amount from `reader`. Truncate amount is set in `result`.
    /// returns `true` if `offset` matches [IPSPatch::EOF], otherwise `false`.
    fn try_read_eof(reader: &mut impl Read, offset: u32) -> Option<Result<ReadHunkResult, Error>> {
        if offset == u32::from_u24_be_bytes(IPSPatch::EOF) {
            return Some(Self::read_trunc(reader));
        }
        return None;
    }


    /// reads an [IPSHunk] from `reader` and adds it to `result`.
    /// returns `true` if a hunk was read, otherwise `false` if [IPSPatch::EOF] was read.
    fn try_read(reader: &mut impl Read) -> Result<ReadHunkResult, Error> {
        let offset = reader.read_u24_be("Unable to parse offset.".to_string())?;
        // try to read eof first
        if let Some(result) = Self::try_read_eof(reader, offset) {
            return Ok(result?);
        }
        let length = reader.read_u16_be("Unable to read length.".to_string())?;
        // rle hunks have their length field set to zero
        if length == 0 {
            Ok(ReadHunkResult::Hunk(IPSRLEHunkData::read(reader, offset)?))
        } else {
            Ok(ReadHunkResult::Hunk(IPSRegularHunkData::read(reader, offset, length)?))
        }
    }

    /// Applies the hunk to `target`.
    fn apply<T>(&self, target: &mut T) -> Result<(), Error> where T: Seek + Write {
        match self {
            IPSHunk::Regular(x) => x.apply(target),
            IPSHunk::RLE(x) => x.apply(target)
        }
    }
}

/// Represents an IPS patch file.
#[derive(Debug, PartialEq)]
pub struct IPSPatch {
    /// List of [hunks](IPSHunk) to apply.
    pub hunks: Vec<IPSHunk>,
    /// optional value to truncate patched files to.
    pub truncate: Option<u32>,
}

impl IPSPatch {
    /// Patch header for IPS.
    pub const HEADER: &'static [u8] = "PATCH".as_bytes();

    /// Identifier for an end of patch file.
    pub const EOF: &'static [u8] = "EOF".as_bytes();

    /// constructs an empty [IPSPatch]
    ///
    /// # Examples
    ///
    /// ```
    /// use rom_patcher::ips::IPSPatch;
    /// let patch = IPSPatch::new();
    /// ```
    pub const fn new() -> IPSPatch {
        IPSPatch {
            hunks: Vec::new(),
            truncate: None,
        }
    }

    /// writes `self` to `writer`.
    ///
    /// # Examples
    ///
    /// ```
    /// // writes a patch to a file
    /// use std::fs::File;
    /// use rom_patcher::ips::IPSPatch;
    /// let mut patch_file = File::create("test.ips");
    /// let patch = IPSPatch::new();
    /// patch.write(&mut patch_file).expect("Write failed.");
    /// ```
    pub fn write(&self, writer: &mut impl Write) -> IOResult<()> {
        writer.write_all(IPSPatch::HEADER)?;
        for hunk in &self.hunks {
            match hunk {
                IPSHunk::Regular(data) => data.write(writer)?,
                IPSHunk::RLE(data) => data.write(writer)?,
            }
        };
        writer.write_all(IPSPatch::EOF)?;
        if let Some(truncate) = self.truncate {
            writer.write_all(&truncate.to_u24_be_bytes())?;
        }
        Ok(())
    }
    /// adds `hunk` to patch.
    ///
    /// # Examples
    ///
    /// ```
    /// use rom_patcher::ips::{IPSHunk, IPSPatch, IPSRegularHunkData};
    /// let mut patch = IPSPatch::new();
    /// patch.add_hunk(
    ///     IPSHunk::Regular(
    ///         IPSRegularHunkData {
    ///             offset: 0,
    ///             length: 1,
    ///             payload: vec![1].into_boxed_slice()
    ///         }
    ///     )
    /// )
    /// ```
    pub fn add_hunk(&mut self, hunk: IPSHunk) {
        self.hunks.push(hunk);
    }
    /// returns a new patch with a given `hunk`.
    ///
    /// # Examples
    ///
    /// ```
    /// use rom_patcher::ips::{IPSHunk, IPSPatch, IPSRegularHunkData};
    /// let mut patch = IPSPatch::new()
    ///     .with_hunk(
    ///         IPSHunk::Regular(
    ///             IPSRegularHunkData {
    ///                 offset: 0,
    ///                 length: 1,
    ///                 payload: vec![1].into_boxed_slice(),
    ///             }
    ///         )
    ///     );
    /// ```
    pub fn with_hunk(mut self, hunk: IPSHunk) -> Self {
        self.add_hunk(hunk);
        return self;
    }

    /// returns a new patch with `truncate` set.
    ///
    /// # Examples
    ///
    /// ```
    /// use rom_patcher::ips::IPSPatch;
    /// // create a patch file that should truncate patched file to 32 bytes
    /// let patch = IPSPatch::new()
    ///     .with_truncate(32);
    /// ```
    pub fn with_truncate(mut self, truncate: u32) -> Self {
        self.truncate = Some(truncate);
        return self;
    }

    /// Reads data from `reader` and returns [PatchParsingError] if [IPSPatch::HEADER] was not read.
    fn read_header(reader: &mut impl Read) -> Result<(), Error> {
        reader.assert_read(
            IPSPatch::HEADER,
            "Unable to parse header.".to_string(),
            "Invalid header.".to_string(),
        )
    }


    /// Reads an [IPSPatch] from `reader`
    ///
    /// # Examples
    ///
    /// ```
    /// use std::fs::File;
    /// use rom_patcher::ips::IPSPatch;
    ///
    /// // reads a patch file
    /// let mut file = File::open("patch.ips");
    /// let patch = IPSPatch::read_from(&mut file);
    /// ```
    pub fn read_from(reader: &mut impl Read) -> Result<IPSPatch, Error> {
        let mut result = IPSPatch::new();
        Self::read_header(reader)?;
        loop {
            let hunk_result = IPSHunk::try_read(reader)?;
            match hunk_result {
                ReadHunkResult::Hunk(hunk) => {
                    result.hunks.push(hunk);
                }
                ReadHunkResult::EOF(value) => {
                    result.truncate = value;
                    return Ok(result);
                }
            }
        }
    }


    /// Applies the patch to `target`.
    pub fn apply<T>(&self, target: &mut T) -> Result<(), Error> where T: Write + Seek + Truncate {
        for hunk in &self.hunks {
            hunk.apply(target)?;
        }
        if let Some(value) = self.truncate {
            target.truncate(value).map_err(|_|Error::new(PatchingError).with_description("Unable to truncate target.".to_string()))?;
        }
        Ok(())
    }
}

/// applies `patch` to `target`.
///
/// This method differs from read and apply from [IPSPatch] because there are no intermediate patch
/// structs and hunks are applied as they are read.
///
/// # Examples
/// ```
/// use std::fs::File;
/// use rom_patcher::ips::apply_ips_patch;
/// use std::error::Error;
///
/// fn main() -> Result<(), dyn Error> {
///     let mut patch_file = File::open("my_patch.ips")?;
///     let mut target_file = File::options().write(true).open("target.bin")?;
///     apply_ips_patch(&mut patch_file, &mut target_file)?;
///     Ok(())
/// }
/// ```
pub fn apply_ips_patch<TPatch, TTarget>(patch: &mut TPatch, target: &mut TTarget) -> Result<(), Error> where TPatch: Read, TTarget: Write + Seek + Truncate {
    IPSPatch::read_header(patch)?;
    loop {
        let hunk_result = IPSHunk::try_read(patch)?;
        match hunk_result {
            ReadHunkResult::Hunk(hunk) => {
                hunk.apply(target)?;
            }
            ReadHunkResult::EOF(trunc) => {
                if let Some(value) = trunc {
                    target.truncate(value).map_err(|_|Error::new(PatchingError).with_description("Unable to truncate target.".to_string()))?;
                }
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use test_data::*;

    use crate::test_util::*;

    use super::*;

    mod test_data {
        use super::*;

        pub const EMPTY_PATCH: IPSPatch = IPSPatch::new();

        pub fn empty_patch_data() -> Vec<u8> {
            Vec::new()
                .build_with_slice(IPSPatch::HEADER)
                .build_with_slice(IPSPatch::EOF)
        }

        pub fn patch_with_regular_hunk() -> IPSPatch {
            IPSPatch::new()
                .with_hunk(IPSHunk::Regular(IPSRegularHunkData {
                    offset: 258,
                    length: 2,
                    payload: Box::new([0xAA, 0xBB]),
                }))
        }

        pub fn patch_with_regular_hunk_data() -> Vec<u8> {
            Vec::new()
                .build_with_slice(IPSPatch::HEADER)
                .build_with_slice(&[0x0, 0x1, 0x2]) // offset
                .build_with_slice(&[0x0, 0x2]) // length
                .build_with_slice(&[0xAA, 0xBB])// payload
                .build_with_slice(IPSPatch::EOF)
        }

        pub fn patch_with_rle_hunk() -> IPSPatch {
            IPSPatch::new()
                .with_hunk(IPSHunk::RLE(IPSRLEHunkData {
                    offset: 258,
                    run_length: 43707,
                    payload: 0xCC,
                }))
        }

        pub fn patch_with_rle_hunk_data() -> Vec<u8> {
            Vec::new()
                .build_with_slice(IPSPatch::HEADER)
                .build_with_slice(&[0x0, 0x1, 0x2]) // offset
                .build_with_slice(&[0x0, 0x0]) // length
                .build_with_slice(&[0xAA, 0xBB]) // run_length
                .build_with_slice(&[0xCC])// payload
                .build_with_slice(IPSPatch::EOF)
        }

        pub fn patch_with_multiple_hunks() -> IPSPatch {
            IPSPatch::new()
                .with_hunk(IPSHunk::Regular(IPSRegularHunkData {
                    offset: 258,
                    length: 2,
                    payload: Box::new([0xAA, 0xBB]),
                }))
                .with_hunk(IPSHunk::RLE(IPSRLEHunkData {
                    offset: 258,
                    run_length: 43707,
                    payload: 0xCC,
                }))
                .with_truncate(32)
        }

        pub fn patch_with_multiple_hunks_data() -> Vec<u8> {
            Vec::new()
                .build_with_slice(IPSPatch::HEADER)

                // regular hunk
                .build_with_slice(&[0x0, 0x1, 0x2]) // offset
                .build_with_slice(&[0x0, 0x2]) // length
                .build_with_slice(&[0xAA, 0xBB])// payload

                // rle hunk
                .build_with_slice(&[0x0, 0x1, 0x2]) // offset
                .build_with_slice(&[0x0, 0x0]) // length
                .build_with_slice(&[0xAA, 0xBB]) // run_length
                .build_with_slice(&[0xCC])// payload
                .build_with_slice(IPSPatch::EOF)
                .build_with_slice(&[0x0, 0x0, 0x20])
        }

        pub fn patch_with_truncate() -> IPSPatch {
            IPSPatch::new()
                .with_truncate(32)
        }

        pub fn patch_with_truncate_data() -> Vec<u8> {
            empty_patch_data()
                .build_with_slice(&[0x0, 0x0, 0x20])
        }
    }

    mod write_tests {
        use super::*;

        #[test]
        fn writing_an_empty_patch_writes_just_header_and_eof() {
            let mut actual = Vec::new();
            EMPTY_PATCH.write(&mut actual).unwrap();
            assert_that!(actual).is_equal_to(empty_patch_data());
        }

        #[test]
        fn write_regular_hunk() {
            let mut actual = Vec::new();
            patch_with_regular_hunk().write(&mut actual).unwrap();
            assert_that!(actual).is_equal_to(patch_with_regular_hunk_data());
        }

        #[test]
        fn write_rle_hunk() {
            let mut actual = Vec::new();
            patch_with_rle_hunk().write(&mut actual).unwrap();
            assert_that!(actual).is_equal_to(patch_with_rle_hunk_data());
        }

        #[test]
        fn write_truncate() {
            let mut actual = Vec::new();
            patch_with_truncate().write(&mut actual).unwrap();
            assert_that!(actual).is_equal_to(patch_with_truncate_data());
        }

        #[test]
        fn write_multiple_hunks() {
            let mut actual = Vec::new();
            patch_with_multiple_hunks().write(&mut actual).unwrap();
            assert_that!(actual).is_equal_to(patch_with_multiple_hunks_data());
        }
    }

    mod read_tests {
        use super::*;

        #[test]
        fn reading_an_empty_patch_reads_just_header_and_eof() {
            let actual = IPSPatch::read_from(&mut empty_patch_data().as_slice()).unwrap();
            assert_that!(actual).is_equal_to(EMPTY_PATCH);
        }

        #[test]
        fn invalid_header() {
            let patch_data = Vec::new()
                .build_with_slice("PATTH".as_bytes()) // corrupted header
                .build_with_slice(IPSPatch::EOF);
            let patch = IPSPatch::read_from(&mut patch_data.as_slice());
            let error = assert_that!(patch)
                .is_err()
                .subject;
            assert_that!(error.to_string())
                .is_equal_to("ParsingError: Invalid header.".to_string());
        }

        #[test]
        fn unable_to_read_header() {
            let patch_data = Vec::new()
                .build_with_slice("PA".as_bytes());
            let patch = IPSPatch::read_from(&mut patch_data.as_slice());
            let err = assert_that!(patch)
                .is_err()
                .subject;

            assert_that!(err.to_string())
                .is_equal_to("ParsingError: Unable to parse header.".to_string());
        }

        #[test]
        fn read_regular_hunk() {
            let actual = IPSPatch::read_from(&mut patch_with_regular_hunk_data().as_slice()).unwrap();
            assert_that!(actual).is_equal_to(patch_with_regular_hunk());
        }

        #[test]
        fn read_rle_hunk() {
            let actual = IPSPatch::read_from(&mut patch_with_rle_hunk_data().as_slice()).unwrap();
            assert_that!(actual).is_equal_to(patch_with_rle_hunk());
        }

        #[test]
        fn read_truncate() {
            let actual = IPSPatch::read_from(&mut patch_with_truncate_data().as_slice()).unwrap();
            assert_that!(actual).is_equal_to(patch_with_truncate());
        }

        #[test]
        fn read_multiple_hunks() {
            let actual = IPSPatch::read_from(&mut patch_with_multiple_hunks_data().as_slice()).unwrap();
            assert_that!(actual).is_equal_to(patch_with_multiple_hunks());
        }
    }

    mod apply_tests {
        use std::io::Cursor;

        use super::*;

        #[test]
        fn apply_empty_patch_does_nothing_to_input() {
            let base: Vec<u8> = (0..16).collect();
            let mut target = Cursor::new(base.clone());
            let patch = EMPTY_PATCH;

            assert_that!(patch.apply(&mut target)).is_ok();
            assert_that!(target.get_ref()).is_equal_to(&base);
        }

        #[test]
        fn apply_regular_hunk() {
            let mut target = Cursor::new((0..16).collect());
            let patch = IPSPatch::new()
                .with_hunk(IPSHunk::Regular(IPSRegularHunkData {
                    offset: 1,
                    length: 3,
                    payload: Box::new([0xa, 0xb, 0xc]),
                }));
            let expected = vec![0x0, 0xa, 0xb, 0xc, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF];

            assert_that!(patch.apply(&mut target)).is_ok();
            assert_that!(target.get_ref()).is_equal_to(&expected);
        }

        #[test]
        fn apply_rle_hunk() {
            let mut target = Cursor::new((0..16).collect());
            let patch = IPSPatch::new()
                .with_hunk(IPSHunk::RLE(IPSRLEHunkData {
                    offset: 1,
                    run_length: 3,
                    payload: 0xa,
                }));
            let expected = vec![0x0, 0xa, 0xa, 0xa, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF];

            assert_that!(patch.apply(&mut target)).is_ok();
            assert_that!(target.get_ref()).is_equal_to(&expected);
        }

        #[test]
        fn apply_truncate() {
            let mut target = Cursor::new((0..16).collect());
            let patch = IPSPatch::new()
                .with_hunk(IPSHunk::RLE(IPSRLEHunkData {
                    offset: 1,
                    run_length: 3,
                    payload: 0xa,
                }))
                .with_truncate(8);
            let expected = vec![0x0, 0xa, 0xa, 0xa, 0x4, 0x5, 0x6, 0x7];

            assert_that!(patch.apply(&mut target)).is_ok();
            assert_that!(target.get_ref()).is_equal_to(&expected);
        }
    }

    mod stream_apply_ips_patch_tests {
        use std::io::Cursor;

        use super::*;

        #[test]
        fn applying_an_empty_patch_does_nothing() {
            let base: Vec<u8> = (0..15).collect();
            let mut target_cur: Cursor<Vec<u8>> = Cursor::new(base.clone());
            assert_that!(apply_ips_patch(&mut empty_patch_data().as_slice(), &mut target_cur)).is_ok();
            assert_that(target_cur.get_ref()).is_equal_to(base);
        }

        #[test]
        fn invalid_header() {
            let base: Vec<u8> = (0..15).collect();
            let mut target_cur: Cursor<Vec<u8>> = Cursor::new(base.clone());
            let patch_data = Vec::new()
                .build_with_slice("PATTH".as_bytes()) // corrupted header
                .build_with_slice(IPSPatch::EOF);
            let result = apply_ips_patch(&mut patch_data.as_slice(), &mut target_cur);
            let error = assert_that!(result)
                .is_err()
                .subject;
            assert_that!(error.to_string())
                .is_equal_to("ParsingError: Invalid header.".to_string());
        }

        #[test]
        fn unable_to_read_header() {
            let base: Vec<u8> = (0..15).collect();
            let mut target_cur: Cursor<Vec<u8>> = Cursor::new(base.clone());
            let patch_data = Vec::new()
                .build_with_slice("PA".as_bytes());
            let result = apply_ips_patch(&mut patch_data.as_slice(), &mut target_cur);

            let err = assert_that!(result)
                .is_err()
                .subject;

            assert_that!(err.to_string())
                .is_equal_to("ParsingError: Unable to parse header.".to_string());
        }

        #[test]
        fn read_and_apply_regular_hunk() {
            let mut target = Cursor::new((0..16).collect::<Vec<u8>>());
            let patch = IPSPatch::new()
                .with_hunk(IPSHunk::Regular(IPSRegularHunkData {
                    offset: 1,
                    length: 3,
                    payload: Box::new([0xa, 0xb, 0xc]),
                }));
            let mut patch_data = Vec::new();
            patch.write(&mut patch_data).unwrap();
            apply_ips_patch(&mut patch_data.as_slice(), &mut target).unwrap();

            assert_that!(target.get_ref()).is_equal_to(&vec![0, 0xa, 0xb, 0xc, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        }

        #[test]
        fn read_and_apply_rle_hunk() {
            let mut target = Cursor::new((0..16).collect::<Vec<u8>>());
            let patch = IPSPatch::new()
                .with_hunk(IPSHunk::RLE(IPSRLEHunkData {
                    offset: 1,
                    run_length: 3,
                    payload: 0xa,
                }));
            let mut patch_data = Vec::new();
            patch.write(&mut patch_data).unwrap();
            apply_ips_patch(&mut patch_data.as_slice(), &mut target).unwrap();

            assert_that!(target.get_ref()).is_equal_to(&vec![0, 0xa, 0xa, 0xa, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        }

        #[test]
        fn read_and_apply_truncate() {
            let mut target = Cursor::new((0..16).collect::<Vec<u8>>());
            let patch = IPSPatch::new()
                .with_hunk(IPSHunk::RLE(IPSRLEHunkData {
                    offset: 1,
                    run_length: 3,
                    payload: 0xa,
                }))
                .with_truncate(8);
            let mut patch_data = Vec::new();
            patch.write(&mut patch_data).unwrap();
            apply_ips_patch(&mut patch_data.as_slice(), &mut target).unwrap();

            assert_that!(target.get_ref()).is_equal_to(&vec![0, 0xa, 0xa, 0xa, 4, 5, 6, 7]);
        }

        #[test]
        fn read_multiple_hunks() {
            let mut target = Cursor::new((0..16).collect::<Vec<u8>>());
            let patch = IPSPatch::new()
                .with_hunk(IPSHunk::RLE(IPSRLEHunkData {
                    offset: 1,
                    run_length: 3,
                    payload: 0xa,
                }))
                .with_hunk(IPSHunk::Regular(IPSRegularHunkData {
                    offset: 4,
                    length: 3,
                    payload: Box::new([0xb, 0xc, 0xd])
                }));
            let mut patch_data = Vec::new();
            patch.write(&mut patch_data).unwrap();
            apply_ips_patch(&mut patch_data.as_slice(), &mut target).unwrap();

            assert_that!(target.get_ref()).is_equal_to(&vec![0, 0xa, 0xa, 0xa, 0xb, 0xc, 0xd, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        }
    }
}
