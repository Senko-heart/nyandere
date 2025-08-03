pub mod compact;

use std::cmp::Ordering;
use std::str::Utf8Error;

use compact_str::CompactString as String;
use foldhash::HashMap;
use foldhash::HashSet;
use sha3::Digest;
use sha3::Sha3_224;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        UnexpectedEof
        BadMagic
        BadAddress
        BadFunctionName
        EpilogueNotEmpty
        DecodeUtf16
        DecodeUtf8(err: Utf8Error) { from() }
        UnknownSection(err: [u8; 8])
        BadSection(err: [u8; 8])
        IncompatibleGlobal
        IncompatibleData
        HashMismatch
        NoMods
        ModsConflicts(err: String)
        IO(err: std::io::Error) { from() }
    }
}

type Hash = [u8; 224 / 8];
const MAGIC: &[u8; 56] = b"Entis\x1a\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00Cotopha Image file\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const PROLOGUE: &[u8; 22] = b"@\0I\0n\0i\0t\0i\0a\0l\0i\0z\0e\0";
// const EMPTY_PROLOGUE: &[u8; 33] =
//     b"\x04\x0b\x00\x00\x00@\0I\0n\0i\0t\0i\0a\0l\0i\0z\0e\0\x00\x00\x00\x00\x09\x01";

pub struct CSX {
    base_hash: Hash,
    base_func: HashMap<String, usize>,
    mods_used: HashSet<String>,
    global: Vec<u8>,
    data: Vec<u8>,
    functions: Vec<Function>,
}

impl CSX {
    fn new_(csx: &mut &[u8], base: bool) -> Result<Self, Error> {
        let base_hash = if base { sha3_224(csx) } else { <_>::default() };
        let header = csx.split_off(..64).expect_eof()?;
        let _length = header.strip_prefix(MAGIC).expect_magic()?;

        let [
            mut image,
            mut function,
            mut global,
            mut data,
            mut conststr,
            mut linkinf,
        ] = <_>::default();

        while !csx.is_empty() {
            let header = csx.split_off_chunk()?;
            let length = csx.split_off_chunk()?;
            let length = u64::from_le_bytes(length) as usize;
            let contents = csx.split_off(..length).expect_eof()?;
            match &header {
                b"image   " => image = contents,
                b"function" => function = contents,
                b"global  " => global = contents,
                b"data    " => data = contents,
                b"conststr" => conststr = contents,
                b"linkinf " => linkinf = contents,
                _ => return Err(Error::UnknownSection(header)),
            }
        }

        if global.is_empty() {
            return Err(Error::BadSection(*b"global  "));
        }

        if data.is_empty() {
            return Err(Error::BadSection(*b"data    "));
        }

        if !conststr.is_empty() && conststr != [0; 4] {
            return Err(Error::BadSection(*b"conststr"));
        }

        if !linkinf.is_empty() && linkinf != [0; 16] && base {
            return Err(Error::BadSection(*b"linkinf "));
        }

        let mut addr_splits = vec![];

        let length = function.split_off_chunk()?;
        for _ in 0..u32::from_le_bytes(length) {
            let addr = function.split_off_chunk()?;
            let addr = u32::from_le_bytes(addr);
            validate_name(image, addr, PROLOGUE)?;
            addr_splits.push(addr);
        }

        let length = function.split_off_chunk()?;
        if u32::from_le_bytes(length) != 0 {
            return Err(Error::EpilogueNotEmpty);
        }

        let length = function.split_off_chunk()?;
        for _ in 0..u32::from_le_bytes(length) {
            let addr = function.split_off_chunk()?;
            let addr = u32::from_le_bytes(addr);
            let len = function.split_off_chunk()?;
            let len = u32::from_le_bytes(len) as usize;
            let name = function.split_off(..2 * len).expect_eof()?;
            validate_name(image, addr, name)?;
            if name.starts_with(b"@\0") {
                return Err(Error::BadFunctionName);
            }
            addr_splits.push(addr);
        }

        addr_splits.sort_unstable();
        addr_splits.push(image.len() as u32);
        for i in 0..addr_splits.len() - 1 {
            addr_splits[i] = addr_splits[i + 1] - addr_splits[i];
        }
        addr_splits.pop();

        let mut functions = Vec::with_capacity(addr_splits.len());
        for size in addr_splits {
            let name = extract_name(image, 0)?;
            let name = from_utf16(name)?;
            let bytecode = image.split_off(..size as usize).expect_eof()?.to_vec();
            functions.push(Function { name, bytecode });
        }

        let base_func = if base {
            functions
                .iter()
                .enumerate()
                .filter(|(_, f)| !f.name.starts_with("@"))
                .map(|(i, f)| (f.name.clone(), i))
                .collect()
        } else {
            <_>::default()
        };

        Ok(Self {
            base_hash,
            base_func,
            mods_used: <_>::default(),
            global: global.to_vec(),
            data: data.to_vec(),
            functions,
        })
    }

    pub fn new(csx: &mut &[u8]) -> Result<Self, Error> {
        Self::new_(csx, true)
    }

    pub fn new_mods(&self, csx: &mut &[u8]) -> Result<Self, Error> {
        let mut mods = Self::new_(csx, false)?;
        mods.base_hash = self.base_hash;
        Ok(mods)
    }

    // pub fn optimize_prologue(&mut self) {
    //     self.functions
    //         .retain(|f| f.name != "@Initialize" || f.bytecode != EMPTY_PROLOGUE);
    // }

    pub fn rebuild(&self) -> Vec<u8> {
        let mut csx = vec![];
        csx.extend_from_slice(MAGIC);
        csx.extend_from_slice(&[0; 8]);

        csx.extend_from_slice(b"image   ");
        let origin = csx.len();
        csx.extend_from_slice(&[0; 8]);
        for f in &self.functions {
            csx.extend_from_slice(&f.bytecode);
        }
        let size = csx.len() - origin - 8;
        csx[origin..origin + 8].copy_from_slice(&(size as u64).to_le_bytes());

        csx.extend_from_slice(b"function");
        let origin = csx.len();
        csx.extend_from_slice(&[0; 8]);
        let mut addr = 0;
        let (mut prologue, mut function) = (vec![], vec![]);
        for f in &self.functions {
            if f.name == "@Initialize" {
                prologue.push(addr);
            } else {
                let name = extract_name(&f.bytecode, 0).unwrap();
                function.push((addr, name));
            }
            addr += f.bytecode.len() as u32;
        }
        function.sort_by(|(_, f), (_, g)| cmp_utf16(f, g));
        csx.extend_from_slice(&(prologue.len() as u32).to_le_bytes());
        for addr in prologue {
            csx.extend_from_slice(&addr.to_le_bytes());
        }
        csx.extend_from_slice(&(0 as u32).to_le_bytes());
        csx.extend_from_slice(&(function.len() as u32).to_le_bytes());
        for (addr, name) in function {
            csx.extend_from_slice(&addr.to_le_bytes());
            csx.extend_from_slice(&((name.len() / 2) as u32).to_le_bytes());
            csx.extend_from_slice(name);
        }
        let size = csx.len() - origin - 8;
        csx[origin..origin + 8].copy_from_slice(&(size as u64).to_le_bytes());

        csx.extend_from_slice(b"global  ");
        csx.extend_from_slice(&(self.global.len() as u64).to_le_bytes());
        csx.extend_from_slice(&self.global);

        csx.extend_from_slice(b"data    ");
        csx.extend_from_slice(&(self.data.len() as u64).to_le_bytes());
        csx.extend_from_slice(&self.data);

        csx.extend_from_slice(b"conststr");
        csx.extend_from_slice(&(4u64).to_le_bytes());
        csx.extend_from_slice(&(0u32).to_le_bytes());

        csx.extend_from_slice(b"linkinf ");
        csx.extend_from_slice(&(16u64).to_le_bytes());
        for _ in 0..4 {
            csx.extend_from_slice(&(0u32).to_le_bytes());
        }

        let size = csx.len() - 64;
        csx[56..64].copy_from_slice(&(size as u64).to_le_bytes());
        csx
    }

    pub fn concat_mods(all_mods: Vec<CSX>) -> Result<CSX, Error> {
        let mut all_mods = all_mods.into_iter();
        let mut mods = all_mods.next().expect_mods()?;
        for m in all_mods {
            validate_same_hash(&mods, &m)?;

            if m.global.starts_with(&mods.global) {
                mods.global = m.global;
            } else if !mods.global.starts_with(&m.global) {
                return Err(Error::IncompatibleGlobal);
            }

            if m.data.starts_with(&mods.data) {
                mods.data = m.data;
            } else if !mods.data.starts_with(&m.data) {
                return Err(Error::IncompatibleData);
            }

            mods.functions.append(&mut { m.functions });
        }

        Ok(mods)
    }

    pub fn apply_all_mods(&mut self, mods: CSX) -> Result<(), Error> {
        validate_same_hash(self, &mods)?;
        validate_items_same_prefix(self, &mods)?;

        self.global = mods.global;
        self.data = mods.data;
        for f in mods.functions {
            if f.name.starts_with("@") {
                if f.name != "@Initialize" {
                    return Err(Error::BadFunctionName);
                }
                self.functions.push(f);
                continue;
            }

            if !self.mods_used.insert(f.name.clone()) {
                return Err(Error::ModsConflicts(f.name));
            }
            
            if let Some(&index) = self.base_func.get(&f.name) {
                self.functions[index] = f;
            } else {
                self.functions.push(f);
            }
        }
        
        Ok(())
    }
}

fn sha3_224(data: &[u8]) -> Hash {
    let mut hasher = Sha3_224::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn validate_name(image: &[u8], addr: u32, name: &[u8]) -> Result<(), Error> {
    let actual_name = extract_name(image, addr)?;
    if name != actual_name {
        return Err(Error::BadFunctionName);
    }
    Ok(())
}

fn extract_name(image: &[u8], addr: u32) -> Result<&[u8], Error> {
    let mut start = image.get(addr as usize..).expect_addr()?;
    let Ok([4u8]) = start.split_off_chunk() else {
        return Err(Error::BadAddress);
    };
    let length = start.split_off_chunk().ok().expect_addr()?;
    let len = 2 * (u32::from_le_bytes(length) as usize);
    start.get(..len).expect_addr()
}

fn validate_same_hash(base: &CSX, mods: &CSX) -> Result<(), Error> {
    if base.base_hash != mods.base_hash {
        return Err(Error::HashMismatch);
    }

    Ok(())
}

fn validate_items_same_prefix(base: &CSX, mods: &CSX) -> Result<(), Error> {
    if !base.global.starts_with(&mods.global) {
        return Err(Error::IncompatibleGlobal);
    }

    if !base.data.starts_with(&mods.data) {
        return Err(Error::IncompatibleData);
    }

    Ok(())
}

fn from_utf16(bytes: &[u8]) -> Result<String, Error> {
    String::from_utf16le(bytes).map_err(|_| Error::DecodeUtf16)
}

fn cmp_utf16(lhs: &[u8], rhs: &[u8]) -> Ordering {
    let (lhs, _) = lhs.as_chunks();
    let (rhs, _) = rhs.as_chunks();
    for (&l, &r) in std::iter::zip(lhs, rhs) {
        match u16::from_le_bytes(l).cmp(&u16::from_le_bytes(r)) {
            Ordering::Equal => (),
            other => return other,
        }
    }
    lhs.len().cmp(&rhs.len())
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub bytecode: Vec<u8>,
}

trait OptionExt<T>: Sized {
    fn expect<F: FnOnce() -> Error>(self, err: F) -> Result<T, Error>;

    fn expect_eof(self) -> Result<T, Error> {
        self.expect(|| Error::UnexpectedEof)
    }

    fn expect_magic(self) -> Result<T, Error> {
        self.expect(|| Error::BadMagic)
    }

    fn expect_addr(self) -> Result<T, Error> {
        self.expect(|| Error::BadAddress)
    }

    fn expect_mods(self) -> Result<T, Error> {
        self.expect(|| Error::NoMods)
    }
}

impl<T> OptionExt<T> for Option<T> {
    fn expect<F: FnOnce() -> Error>(self, err: F) -> Result<T, Error> {
        self.ok_or_else(err)
    }
}

trait SliceExt: Sized {
    fn split_off_chunk<const N: usize>(&mut self) -> Result<[u8; N], Error>;
}

impl SliceExt for &[u8] {
    fn split_off_chunk<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let chunk;
        (chunk, *self) = self.split_first_chunk().expect_eof()?;
        Ok(*chunk)
    }
}
