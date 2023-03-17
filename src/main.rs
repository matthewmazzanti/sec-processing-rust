mod util;

#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::{ env, fs };
use std::io::Read;
use std::borrow::Cow;
use anyhow::Context;
use camino::{ Utf8Path as Path, Utf8PathBuf as PathBuf };
use argh::FromArgs;
use rayon::prelude::*;
use memmap2::MmapOptions;
use flate2::bufread::DeflateDecoder;
use zstd::stream::read::Decoder as ZstdDecoder;
use encoding_rs::Encoding;
use chardetng::EncodingDetector;
use zip_parser::{ compress, Zip64Archive };
use util::{ Decoder, Crc32Checker };

use serde::Deserialize;
use lazy_static::lazy_static;
use regex::Regex;

/*
   type SecData struct {
   Filings struct {
   Recent SecFilings `json:"recent"`
   Files []SecFile `json:"files"`
   } `json:"filings"`
   }
   */
#[derive(Deserialize, Debug)]
#[serde(rename_all="camelCase")]
#[allow(dead_code)]
struct SecData<'a> {
    #[serde(borrow)]
    filings: SecRecentFilings<'a>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all="camelCase")]
#[allow(dead_code)]
struct SecRecentFilings<'a> {
    #[serde(borrow)]
    recent: SecFilings<'a>,
    #[serde(borrow)]
    files: Vec<SecFile<'a>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all="camelCase")]
#[allow(dead_code)]
struct SecFile<'a> {
    name: &'a str,
    filing_count: i64,
    filing_from: &'a str,
    filing_to: &'a str,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all="camelCase")]
#[allow(dead_code)]
struct SecFilings<'a> {
    #[serde(borrow)]
    accession_number: Vec<&'a str>,
    #[serde(borrow)]
    filing_date: Vec<&'a str>,
    #[serde(borrow)]
    report_date: Vec<&'a str>,
    #[serde(borrow)]
    acceptance_date_time: Vec<&'a str>,
    #[serde(borrow)]
    act: Vec<&'a str>,
    #[serde(borrow)]
    form: Vec<&'a str>,
    #[serde(borrow)]
    file_number: Vec<&'a str>,
    #[serde(borrow)]
    items: Vec<&'a str>,
    size: Vec<Option<i64>>,
    #[serde(rename="isXBRL")]
    is_xbrl: Vec<i64>,
    #[serde(rename="isInlineXBRL")]
    is_inline_xbrl: Vec<i64>,
    #[serde(borrow)]
    primary_document: Vec<&'a str>,
    #[serde(borrow)]
    primary_doc_description: Vec<Cow<'a, str>>,
}

/*
   type SecFiling struct {
   AccessionNumber string `json:"accessionNumber"`
   FilingDate string `json:"filingDate"`
   ReportDate string `json:"reportDate"`
   AcceptanceDateTime string `json:"acceptanceDateTime"`
   Act string `json:"act"`
   Form string `json:"form"`
   FileNumber string `json:"fileNumber"`
   Items string `json:"items"`
   Size int `json:"size"`
   IsXBRL int `json:"isXBRL"`
   IsInlineXBRL int `json:"isInlineXBRL"`
   PrimaryDocument string `json:"primaryDocument"`
   PrimaryDocDescription string `json:"primaryDocDescription"`
   }
   */


/// unzipx - extract compressed files in a ZIP archive
#[derive(FromArgs)]
struct Options {
    /// path of the ZIP archive(s).
    #[argh(positional)]
    file: Vec<PathBuf>,

    /// an optional directory to which to extract files.
    #[argh(option, short = 'd')]
    exdir: Option<PathBuf>,

    /// specify character set used to decode filename, which will be automatically detected by default.
    #[argh(option, short = 'O')]
    charset: Option<String>
}

fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    let target_dir = if let Some(exdir) = options.exdir {
        exdir
    } else {
        let path = env::current_dir()?;
        PathBuf::from_path_buf(path).ok().context("must utf8 path")?
    };
    let charset = if let Some(label) = options.charset {
        Some(Encoding::for_label(label.as_bytes()).context("invalid encoding label")?)
    } else {
        None
    };

    for file in options.file.iter() {
        unzip(charset, &target_dir, file)?;
    }

    Ok(())
}

fn unzip(charset: Option<&'static Encoding>, target_dir: &Path, path: &Path) -> anyhow::Result<()> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^CIK\d{10}.json$").unwrap();
    }

    println!("Archive: {}", path);

    let fd = fs::File::open(path)?;
    let buf = unsafe {
        MmapOptions::new().map_copy_read_only(&fd)?
    };

    /*
       let buf = fs::read(path)?;
       println!("read");
       */

    let zip = Zip64Archive::parse(&buf)?;
    zip.entries()?.par_bridge().for_each(|cfh| {
        let cfh = cfh.expect("didn't get a cfh");
        let (_, buf) = zip.read(&cfh).expect("couldn't read");

        let name = if let Some(encoding) = charset {
            let (name, ..) = encoding.decode(cfh.name);
            name
        } else if let Ok(name) = std::str::from_utf8(cfh.name) {
            Cow::Borrowed(name)
        } else {
            let mut encoding_detector = EncodingDetector::new();
            encoding_detector.feed(cfh.name, true);
            let (name, ..) = encoding_detector.guess(None, false).decode(cfh.name);
            name
        };

        if !RE.is_match(&name) {
            return
        }

        let reader = match cfh.method {
            compress::STORE => Decoder::None(buf),
            compress::DEFLATE => Decoder::Deflate(DeflateDecoder::new(buf)),
            compress::ZSTD => Decoder::Zstd(ZstdDecoder::with_buffer(buf).expect("couldn't create zstd decoder")),
            _ => panic!("idk"),
        };
        // prevent zipbomb
        let reader = reader.take(cfh.uncomp_size.into());
        let mut reader = Crc32Checker::new(reader, cfh.crc32);

        let mut data = Vec::with_capacity(cfh.uncomp_size.try_into().unwrap());
        reader.read_to_end(&mut data).expect("read error");

        let _: SecData = match simd_json::serde::from_slice(&mut data) {
            Ok(res) => {
                res
            },
            Err(e) => {
                println!("{}", e);
                return
            },
        };
    });

    Ok(())
}
