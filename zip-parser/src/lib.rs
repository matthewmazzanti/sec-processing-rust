//! https://www.hanshq.net/zip.html#zip

mod util;

use thiserror::Error;
use memchr::memmem::rfind;
use util::{ Eof, take, read_u16, read_u32, read_u64 };


pub mod compress {
    pub const STORE: u16   = 0;
    pub const DEFLATE: u16 = 8;
    pub const ZSTD: u16    = 93;
}

pub mod system {
    pub const DOS: u16 = 0;
    pub const UNIX: u16 = 3;
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("eof")]
    Eof,
    #[error("bad eocdr magic number")]
    BadEocdr,

    #[error("bad zip64 eocdl magic number")]
    BadZip64Eocdl,
    #[error("bad cfh magic number")]
    BadCfh,
    #[error("bad lfh magic number")]
    BadLfh,
    #[error("not supported")]
    Unsupported,
    #[error("offset overflow")]
    OffsetOverflow,

    #[error("TODO")]
    TODO
}

impl From<Eof> for Error {
    #[inline]
    fn from(_err: Eof) -> Error {
        Error::Eof
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub struct EocdRecord<'a> {
    pub disk_nbr: u16,
    pub cd_start_disk: u16,
    pub disk_cd_entries: u16,
    pub cd_entries: u16,
    pub cd_size: u32,
    pub cd_offset: u32,
    pub comment: &'a [u8]
}

impl EocdRecord<'_> {
    const SIGNATURE: &[u8; 4] = &[b'P', b'K', 5, 6];

    pub fn find_sig_offset(buf: &[u8]) -> Result<usize, Error> {
        const MAX_BACK_OFFSET: usize = 1024 * 128;

        let search_offset = buf.len()
            .checked_sub(MAX_BACK_OFFSET)
            .unwrap_or(0);


        let foobar = &buf[search_offset..];
        let offset = rfind(foobar, Self::SIGNATURE)
            .ok_or(Error::BadEocdr)?;

        Ok(search_offset + offset)
    }

    pub fn find(buf: &[u8]) -> Result<(usize, EocdRecord<'_>), Error> {
        let offset = Self::find_sig_offset(buf)?;
        let buf = &buf[offset..];
        let (_, record) = EocdRecord::parse(buf)?;

        Ok((offset, record))
    }

    pub fn parse(buf: &[u8]) -> Result<(&[u8], EocdRecord<'_>), Error> {
        let (buf, sig) = take(buf, Self::SIGNATURE.len())?;
        if sig != Self::SIGNATURE {
            return Err(Error::BadEocdr)
        }

        let (buf, disk_nbr) = read_u16(buf)?;
        let (buf, cd_start_disk) = read_u16(buf)?;
        let (buf, disk_cd_entries) = read_u16(buf)?;
        let (buf, cd_entries) = read_u16(buf)?;
        let (buf, cd_size) = read_u32(buf)?;
        let (buf, cd_offset) = read_u32(buf)?;
        let (buf, comment_len) = read_u16(buf)?;
        let (buf, comment) = take(buf, comment_len.into())?;

        Ok((buf, EocdRecord {
            disk_nbr,
            cd_start_disk,
            disk_cd_entries,
            cd_entries,
            cd_size,
            cd_offset,
            comment
        }))
    }
}

/*
 * 4.3.14  Zip64 end of central directory record
 *      zip64 end of central dir
 *      signature                       4 bytes  (0x06064b50)
 *      size of zip64 end of central
 *      directory record                8 bytes
 *      version made by                 2 bytes
 *      version needed to extract       2 bytes
 *      number of this disk             4 bytes
 *      number of the disk with the 
 *      start of the central directory  4 bytes
 *      total number of entries in the
 *      central directory on this disk  8 bytes
 *      total number of entries in the
 *      central directory               8 bytes
 *      size of the central directory   8 bytes
 *      offset of start of central
 *      directory with respect to
 *      the starting disk number        8 bytes
 *      zip64 extensible data sector    (variable size)
 */

#[non_exhaustive]
#[derive(Debug)]
pub struct Zip64EocdRecord<'a> {
    pub version_by: u16,
    pub version_needed: u16,
    pub disk_nbr: u32,
    pub cd_start_disk: u32,
    pub disk_cd_entries: u64,
    pub cd_entries: u64,
    pub cd_size: u64,
    pub cd_offset: u64,
    pub extra_data: &'a [u8]
}

impl Zip64EocdRecord<'_> {
    const SIGNATURE: &[u8; 4] = &[b'P', b'K', 6, 6];

    pub fn parse(buf: &[u8]) -> Result<(&[u8], Zip64EocdRecord<'_>), Error> {
        const SIZE_OF_FIXED_FIELDS: u64 = 44;

        let (buf, sig) = take(buf, Self::SIGNATURE.len())?;
        if sig != Self::SIGNATURE {
            return Err(Error::BadEocdr)
        }

        let (buf, size) = read_u64(buf)?;
        let extra_data_size: usize = size
            .checked_sub(SIZE_OF_FIXED_FIELDS)
            .ok_or(Error::BadEocdr)? // Data size too small
            .try_into()
            .map_err(|_| Error::BadEocdr)?; // Bad conversion from u64 -> usize

        let (buf, version_by) = read_u16(buf)?;
        let (buf, version_needed) = read_u16(buf)?;
        let (buf, disk_nbr) = read_u32(buf)?;
        let (buf, cd_start_disk) = read_u32(buf)?;
        let (buf, disk_cd_entries) = read_u64(buf)?;
        let (buf, cd_entries) = read_u64(buf)?;
        let (buf, cd_size) = read_u64(buf)?;
        let (buf, cd_offset) = read_u64(buf)?;
        let (buf, extra_data) = take(buf, extra_data_size)?;

        Ok((buf, Zip64EocdRecord {
            version_by,
            version_needed,
            disk_nbr,
            cd_start_disk,
            disk_cd_entries,
            cd_entries,
            cd_size,
            cd_offset,
            extra_data,
        }))
    }
}

/*
 * 4.3.15 Zip64 end of central directory locator
 *
 *  zip64 end of central dir locator
 *  signature                       4 bytes  (0x07064b50)
 *  number of the disk with the
 *  start of the zip64 end of
 *  central directory               4 bytes
 *  relative offset of the zip64
 *  end of central directory record 8 bytes
 *  total number of disks           4 bytes
 */

#[non_exhaustive]
#[derive(Debug)]
pub struct Zip64EocdLocator {
    pub cd_start_disk: u32,
    pub offset: u64,
    pub num_disks: u32,
}

impl Zip64EocdLocator {
    const SIGNATURE: &[u8; 4] = &[b'P', b'K', 6, 7];
    const LENGTH: usize = 20;

    pub fn find(buf: &[u8], eocdr_offset: usize) -> Result<Self, Error> {
        let offset = eocdr_offset
            .checked_sub(Self::LENGTH)
            .ok_or(Error::BadZip64Eocdl)?;

        let buf = &buf[offset..eocdr_offset];
        let (_, record) = Self::parse(buf)?;
        Ok(record)
    }

    pub fn parse(buf: &[u8]) -> Result<(&[u8], Self), Error> {
        let (buf, sig) = take(buf, Self::SIGNATURE.len())?;
        if sig != Self::SIGNATURE {
            return Err(Error::BadZip64Eocdl)
        }

        let (buf, cd_start_disk) = read_u32(buf)?;
        let (buf, offset) = read_u64(buf)?;
        let (buf, num_disks) = read_u32(buf)?;

        Ok((buf, Zip64EocdLocator {
            cd_start_disk,
            offset,
            num_disks,
        }))
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub struct CentralFileHeader<'a> {
    pub made_by_ver: u16,
    pub extract_ver: u16,
    pub gp_flag: u16,
    pub method: u16,
    pub mod_time: u16,
    pub mod_date: u16,
    pub crc32: u32,
    pub comp_size: u32,
    pub uncomp_size: u32,
    pub disk_nbr_start: u16,
    pub int_attrs: u16,
    pub ext_attrs: u32,
    pub lfh_offset: u32,
    pub name: &'a [u8],
    pub extra: &'a [u8],
    pub comment: &'a [u8]
}

impl CentralFileHeader<'_> {
    const SIGNATURE: &[u8; 4] = &[b'P', b'K', 1, 2];

    fn parse(buf: &[u8]) -> Result<(&[u8], CentralFileHeader<'_>), Error> {
        let (buf, expect_sig) = take(buf, Self::SIGNATURE.len())?;
        if expect_sig != Self::SIGNATURE {
            return Err(Error::BadCfh);
        }

        let (buf, made_by_ver) = read_u16(buf)?;
        let (buf, extract_ver) = read_u16(buf)?;
        let (buf, gp_flag) = read_u16(buf)?;
        let (buf, method) = read_u16(buf)?;
        let (buf, mod_time) = read_u16(buf)?;
        let (buf, mod_date) = read_u16(buf)?;
        let (buf, crc32) = read_u32(buf)?;
        let (buf, comp_size) = read_u32(buf)?;
        let (buf, uncomp_size) = read_u32(buf)?;
        let (buf, name_len) = read_u16(buf)?;
        let (buf, extra_len) = read_u16(buf)?;
        let (buf, comment_len) = read_u16(buf)?;
        let (buf, disk_nbr_start) = read_u16(buf)?;
        let (buf, int_attrs) = read_u16(buf)?;
        let (buf, ext_attrs) = read_u32(buf)?;
        let (buf, lfh_offset) = read_u32(buf)?;
        let (buf, name) = take(buf, name_len.into())?;
        let (buf, extra) = take(buf, extra_len.into())?;
        let (buf, comment) = take(buf, comment_len.into())?;

        let header = CentralFileHeader {
            made_by_ver,
            extract_ver,
            gp_flag,
            method,
            mod_time,
            mod_date,
            crc32,
            comp_size,
            uncomp_size,
            disk_nbr_start,
            int_attrs,
            ext_attrs,
            lfh_offset,
            name,
            extra,
            comment
        };

        Ok((buf, header))
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub struct LocalFileHeader<'a> {
    pub extract_ver: u16,
    pub gp_flag: u16,
    pub method: u16,
    pub mod_time: u16,
    pub mod_date: u16,
    pub crc32: u32,
    pub comp_size: u32,
    pub uncomp_size: u32,
    pub name: &'a [u8],
    pub extra: &'a [u8]
}

impl LocalFileHeader<'_> {
    const SIGNATURE: &[u8; 4] = &[b'P', b'K', 3, 4];

    fn parse(buf: &[u8]) -> Result<(&[u8], LocalFileHeader<'_>), Error> {
        let (buf, expect_sig) = take(buf, Self::SIGNATURE.len())?;
        if expect_sig != Self::SIGNATURE {
            return Err(Error::BadLfh);
        }

        let (buf, extract_ver) = read_u16(buf)?;
        let (buf, gp_flag) = read_u16(buf)?;
        let (buf, method) = read_u16(buf)?;
        let (buf, mod_time) = read_u16(buf)?;
        let (buf, mod_date) = read_u16(buf)?;
        let (buf, crc32) = read_u32(buf)?;
        let (buf, comp_size) = read_u32(buf)?;
        let (buf, uncomp_size) = read_u32(buf)?;
        let (buf, name_len) = read_u16(buf)?;
        let (buf, extra_len) = read_u16(buf)?;
        let (buf, name) = take(buf, name_len.into())?;
        let (buf, extra) = take(buf, extra_len.into())?;

        let header = LocalFileHeader {
            extract_ver,
            gp_flag,
            method,
            mod_time,
            mod_date,
            crc32,
            comp_size,
            uncomp_size,
            name,
            extra
        };

        Ok((buf, header))
    }
}

pub struct ZipArchive<'a> {
    buf: &'a [u8],
    eocdr: EocdRecord<'a>
}

impl ZipArchive<'_> {
    pub fn parse(buf: &[u8]) -> Result<ZipArchive<'_>, Error> {
        let (_, eocdr) = EocdRecord::find(buf)?;

        if eocdr.disk_nbr != 0
            || eocdr.cd_start_disk != 0
            || eocdr.disk_cd_entries != eocdr.cd_entries
        {
            return Err(Error::Unsupported);
        }

        Ok(ZipArchive { buf, eocdr })
    }

    pub fn eocdr(&self) -> &EocdRecord<'_> {
        &self.eocdr
    }

    pub fn entries(&self) -> Result<ZipEntries<'_>, Error> {
        let offset: usize = self.eocdr.cd_offset.try_into()
            .map_err(|_| Error::OffsetOverflow)?;
        let buf = self.buf.get(offset..)
            .ok_or(Error::OffsetOverflow)?;
        let count = self.eocdr.cd_entries;

        Ok(ZipEntries { buf, count })
    }

    pub fn read<'a>(&'a self, cfh: &CentralFileHeader) -> Result<(LocalFileHeader<'a>, &'a [u8]), Error> {
        let offset: usize = cfh.lfh_offset.try_into()
            .map_err(|_| Error::OffsetOverflow)?;
        let buf = self.buf.get(offset..)
            .ok_or(Error::OffsetOverflow)?;

        let (input, lfh) = LocalFileHeader::parse(buf)?;

        let size = cfh.comp_size.try_into()
            .map_err(|_| Error::OffsetOverflow)?;
        let (_, buf) = take(input, size)?;

        Ok((lfh, buf))
    }
}

pub struct ZipEntries<'a> {
    buf: &'a [u8],
    count: u16
}

impl<'a> Iterator for ZipEntries<'a> {
    type Item = Result<CentralFileHeader<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let new_count = self.count.checked_sub(1)?;

        let input = self.buf;
        let (input, cfh) = match CentralFileHeader::parse(input) {
            Ok(output) => output,
            Err(err) => return Some(Err(err))
        };

        self.buf = input;
        self.count = new_count;

        Some(Ok(cfh))
    }
}

pub struct Zip64Archive<'a> {
    buf: &'a [u8],
    eocdr: EocdRecord<'a>,
    zip64_eocdr: Zip64EocdRecord<'a>,
}

impl Zip64Archive<'_> {
    pub fn parse(buf: &[u8]) -> Result<Zip64Archive<'_>, Error> {
        let (eocdr_offset, eocdr) = EocdRecord::find(&buf)?;
        println!("{:?}", eocdr);

        if eocdr.disk_nbr != 0
            || eocdr.cd_start_disk != 0
            || eocdr.disk_cd_entries != eocdr.cd_entries
        {
            return Err(Error::Unsupported);
        }

        let zip64_eocdl = Zip64EocdLocator::find(&buf, eocdr_offset)?;
        println!("{:?}", zip64_eocdl);

        let zip64_eocdr_offset: usize = zip64_eocdl.offset
            .try_into()
            .map_err(|_| Error::TODO)?;

        let (_, zip64_eocdr) = Zip64EocdRecord::parse(&buf[zip64_eocdr_offset..])?;
        println!("{:?}", zip64_eocdr);

        Ok(Zip64Archive { buf, eocdr, zip64_eocdr })
    }

    pub fn eocdr(&self) -> &EocdRecord<'_> {
        &self.eocdr
    }

    pub fn entries(&self) -> Result<Zip64Entries<'_>, Error> {
        let offset: usize = self.zip64_eocdr.cd_offset
            .try_into()
            .map_err(|_| Error::OffsetOverflow)?;

        let buf = self.buf
            .get(offset..)
            .ok_or(Error::OffsetOverflow)?;

        let count = self.zip64_eocdr.cd_entries;

        Ok(Zip64Entries { buf, count })
    }

    pub fn read<'a>(&'a self, cfh: &CentralFileHeader) -> Result<(LocalFileHeader<'a>, &'a [u8]), Error> {
        let offset: usize = cfh.lfh_offset
            .try_into()
            .map_err(|_| Error::OffsetOverflow)?;

        let buf = self.buf
            .get(offset..)
            .ok_or(Error::OffsetOverflow)?;

        let (input, lfh) = LocalFileHeader::parse(buf)?;

        let size = cfh.comp_size
            .try_into()
            .map_err(|_| Error::OffsetOverflow)?;

        let (_, buf) = take(input, size)?;

        Ok((lfh, buf))
    }
}

pub struct Zip64Entries<'a> {
    buf: &'a [u8],
    count: u64
}

impl<'a> Iterator for Zip64Entries<'a> {
    type Item = Result<CentralFileHeader<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let new_count = self.count.checked_sub(1)?;

        let input = self.buf;
        let (input, cfh) = match CentralFileHeader::parse(input) {
            Ok(output) => output,
            Err(err) => return Some(Err(err))
        };

        self.buf = input;
        self.count = new_count;

        Some(Ok(cfh))
    }
}
