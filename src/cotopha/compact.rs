use std::io::Read;

use flate2::bufread::ZlibDecoder;
use flate2::bufread::ZlibEncoder;

use super::CSX;
use super::Error;
use super::Function;
use super::Hash;
use super::OptionExt;
use super::SliceExt;
use super::String;

const MAGIC: &[u8; 8] = b"Senko\x1a\x00\x00";
const HSIZE: usize = MAGIC.len() + size_of::<Hash>();
const GLOBAL: &str = " global ";
const DATA: &str = " data ";

pub struct CompactCO {
    base_hash: Hash,
    entries: Vec<CompactEntry>,
}

pub struct CompactEntry {
    pub name: String,
    pub zlib: bool,
    pub data: Vec<u8>,
}

impl CompactCO {
    pub fn new(cco: &mut &[u8]) -> Result<Self, Error> {
        let header = cco.split_off(..HSIZE).expect_eof()?;
        let hash = header.strip_prefix(MAGIC).expect_magic()?;
        let base_hash = Hash::try_from(hash).expect("bad size");

        let mut entries = vec![];
        while !cco.is_empty() {
            let size = cco
                .iter()
                .position(|&byte| (byte & !1) == 0xC0)
                .expect_eof()?;
            let name = cco.split_off(..size).expect_eof()?;
            let name = String::from_utf8(name)?;
            let zlib = *cco.split_off_first().expect_eof()? == 0xC1;
            let len = u32::from_le_bytes(cco.split_off_chunk()?) as usize;
            let data = cco.split_off(..len).expect_eof()?.to_vec();
            entries.push(CompactEntry { name, zlib, data });
        }

        Ok(Self { base_hash, entries })
    }

    pub fn rebuild(&self) -> Vec<u8> {
        let mut cco = vec![];
        cco.extend_from_slice(MAGIC);
        cco.extend_from_slice(&self.base_hash);

        for e in &self.entries {
            cco.extend_from_slice(e.name.as_bytes());
            cco.push(if e.zlib { 0xC1 } else { 0xC0 });
            cco.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
            cco.extend_from_slice(&e.data);
        }
        
        cco
    }

    pub fn compress(base: &CSX, mods: &CSX) -> Result<Self, Error> {
        super::validate_same_hash(base, mods)?;
        super::validate_items_same_prefix(base, mods)?;

        let mut entries = vec![];
        entries.push(CompactEntry::make(
            String::new(GLOBAL),
            Some(&base.global),
            &mods.global,
        )?);
        entries.push(CompactEntry::make(
            String::new(DATA),
            Some(&base.data),
            &mods.data,
        )?);

        for f in &mods.functions {
            let index = base.base_func.get(&f.name);
            let base_data = index.map(|&i| &base.functions[i].bytecode[..]);
            let mods_data = &f.bytecode[..];
            entries.push(CompactEntry::make(f.name.clone(), base_data, mods_data)?);
        }

        Ok(Self {
            base_hash: base.base_hash,
            entries,
        })
    }

    pub fn decompress(&self, base: &CSX) -> Result<CSX, Error> {
        let mut mods = CSX {
            base_hash: self.base_hash,
            base_func: <_>::default(),
            mods_used: <_>::default(),
            global: vec![],
            data: vec![],
            functions: vec![],
        };

        super::validate_same_hash(base, &mods)?;
        super::validate_items_same_prefix(base, &mods)?;

        for e in &self.entries {
            let f = e.unpack(base)?;
            match f.name.as_str() {
                GLOBAL => mods.global = f.bytecode,
                DATA => mods.data = f.bytecode,
                _ => mods.functions.push(f),
            }
        }

        Ok(mods)
    }
}

impl CompactEntry {
    pub fn make(name: String, base_data: Option<&[u8]>, mods_data: &[u8]) -> Result<Self, Error> {
        let mut diff = vec![];
        let stream = if let Some(base_data) = base_data {
            bsdiff::diff(base_data, mods_data, &mut diff)?;
            &diff
        } else {
            mods_data
        };
        let mut z = ZlibEncoder::new(stream, flate2::Compression::best());
        let mut data = vec![];
        z.read_to_end(&mut data)?;

        let zlib = data.len() < mods_data.len();
        if !zlib {
            data.clear();
            data.extend_from_slice(mods_data);
        }

        Ok(Self { name, zlib, data })
    }

    pub fn unpack(&self, base: &CSX) -> Result<Function, Error> {
        if !self.zlib {
            return Ok(Function {
                name: self.name.clone(),
                bytecode: self.data.clone(),
            });
        }

        let base_data = match self.name.as_str() {
            GLOBAL => Some(&base.global[..]),
            DATA => Some(&base.data[..]),
            name => match base.base_func.get(name) {
                index => index.map(|&i| &base.functions[i].bytecode[..]),
            },
        };

        let mut z = ZlibDecoder::new(&self.data[..]);
        let mut diff = vec![];
        z.read_to_end(&mut diff)?;

        let mut data = vec![];
        if let Some(base_data) = base_data {
            bsdiff::patch(base_data, &mut &diff[..], &mut data)?;
        } else {
            data = diff;
        }

        Ok(Function {
            name: self.name.clone(),
            bytecode: data,
        })
    }
}
