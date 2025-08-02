#[macro_use]
extern crate quick_error;

mod cotopha;

use std::path::Path;
use std::path::PathBuf;

use color_print::cprintln;

use crate::cotopha::CSX;
use crate::cotopha::Error;
use crate::cotopha::compact::CompactCO;

#[derive(Default)]
struct Args {
    base: Option<PathBuf>,
    mods: Vec<PathBuf>,
    output: Option<PathBuf>,
    compact: Vec<PathBuf>,
}

fn parse_args() -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_env();
    let mut args = Args::default();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                cprintln!("Cotopha function-level patcher and patch archiver\n");
                
                cprintln!("<s><g>Usage:</> <c>nyandere [OPTIONS]</></>\n");

                cprintln!("<s><g>Options:</></>");
                cprintln!("  <c><s>-b</></>, <c><s>--base</> <<BASE>></>     Base, single, unmodified <B><w><s>.csx</></></>, is required");
                cprintln!("  <c><s>-m</></>, <c><s>--mods</> <<MODS>></>     Mods list, <B><w><s>.co</></></> and <B><w><s>.cco</></></> are supported");
                cprintln!("  <c><s>-o</></>, <c><s>--output</> <<PATH>></>   Apply mods list to the base and save at specified <c>PATH</>");
                cprintln!("  <c><s>-c</></>, <c><s>--compact</> <<PATHS>></> Compress mods list and save them at updated <c>PATHS</> list");
                cprintln!("  <c><s>-h</></>, <c><s>--help</></>            Print help");
                std::process::exit(0);
            }
            Short('b') | Long("base") => {
                args.base = Some(parser.value()?.into());
            }
            Short('m') | Long("mods") => {
                for value in parser.values()? {
                    args.mods.push(value.into());
                }
            }
            Short('o') | Long("output") => {
                args.output = Some(parser.value()?.into());
            }
            Short('c') | Long("compact") => {
                for value in parser.values()? {
                    args.compact.push(value.into());
                }
            }
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(args)
}

fn report_lexopt_error(err: lexopt::Error) -> ! {
    eprintln!("Parse error when trying to parse command line args.");
    eprint!("Reason: ");
    match err {
        lexopt::Error::MissingValue { option } => eprintln!(
            "Missing value for option `{}`.",
            option.as_deref().unwrap_or("None")
        ),
        lexopt::Error::UnexpectedOption(option) => eprintln!("Unexpected option `{option}`."),
        lexopt::Error::UnexpectedArgument(_) => eprintln!("Unexpected argument."),
        lexopt::Error::UnexpectedValue { option, .. } => {
            eprintln!("Unexpected value for option `{option}`.")
        }
        lexopt::Error::ParsingFailed { value, .. } => eprintln!("Failed to parse value `{value}`."),
        lexopt::Error::NonUnicodeValue(_) => eprintln!("Non-unicode value."),
        lexopt::Error::Custom(error) => eprintln!("{error}."),
    }
    std::process::exit(1);
}

fn fs_read(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("IO error when trying to read a file at {path:?}.");
            eprintln!("Reason: {error}.");
            std::process::exit(1);
        }
    }
}

fn fs_write(path: &Path, contents: Vec<u8>) {
    if let Err(error) = std::fs::write(path, contents) {
        eprintln!("IO error when trying to write a file at {path:?}.");
        eprintln!("Reason: {error}.");
        std::process::exit(1);
    }
}

fn new_auto(path: PathBuf, base: Option<&CSX>) -> CSX {
    let data = fs_read(&path);
    let mut data_ptr = data.as_slice();
    let csx = match base {
        None => CSX::new(&mut data_ptr),
        Some(base) => {
            if data.starts_with(b"Entis\x1a\0\0") {
                base.new_mods(&mut data_ptr)
            } else if data.starts_with(b"Senko\x1a\0\0") {
                let cco = new_cco(&path, &data);
                Ok(decompress_cco(&path, &cco, base))
            } else {
                eprintln!("Unrecognized file type for {path:?}.");
                std::process::exit(1);
            }
        }
    };

    match csx {
        Ok(csx) => csx,
        Err(err) => {
            let rem = data_ptr.len();
            let at = data.len() - rem;
            eprintln!("Parse error when trying to create CSX.");
            eprintln!("File: {path:?}");
            eprintln!("Byte offset: {at}");
            report_error_reason(err);
        }
    }
}

fn new_cco(path: &Path, data: &[u8]) -> CompactCO {
    let mut data_ptr = data;
    match CompactCO::new(&mut data_ptr) {
        Ok(cco) => cco,
        Err(err) => {
            let rem = data_ptr.len();
            let at = data.len() - rem;
            eprintln!("Parse error when trying to create CompactCO.");
            eprintln!("File: {path:?}");
            eprintln!("Byte offset: {at}");
            report_error_reason(err);
        }
    }
}

fn decompress_cco(path: &Path, cco: &CompactCO, base: &CSX) -> CSX {
    match cco.decompress(base) {
        Ok(csx) => csx,
        Err(err) => {
            eprintln!("Decompression error during CompactCO to CSX restoration.");
            eprintln!("File: {path:?}");
            report_error_reason(err);
        }
    }
}

fn compress_cco(base: &CSX, mods: &CSX) -> CompactCO {
    match CompactCO::compress(base, mods) {
        Ok(cco) => cco,
        Err(err) => {
            eprintln!("Compression error during CompactCO creation.");
            report_error_reason(err);
        }
    }
}

fn concat_and_apply_mods(base: &mut CSX, all_mods: Vec<CSX>) -> Vec<u8> {
    let mods = match CSX::concat_mods(all_mods) {
        Ok(mods) => mods,
        Err(err) => {
            eprintln!("Failed to concatenate mods.");
            report_error_reason(err);
        }
    };
    if let Err(err) = base.apply_all_mods(mods) {
        eprintln!("Failed to apply mods.");
        report_error_reason(err);
    };
    base.rebuild()
}

fn report_error_reason(err: Error) -> ! {
    eprint!("Reason: ");
    match err {
        Error::UnexpectedEof => eprintln!("Unexpected EOF."),
        Error::BadMagic => eprintln!("Bad magic."),
        Error::BadAddress => eprintln!("Bad address."),
        Error::BadFunctionName => eprintln!("Bad function name."),
        Error::EpilogueNotEmpty => eprintln!("Epilogue is not empty."),
        Error::DecodeUtf16 => eprintln!("Failed to decode utf-16."),
        Error::DecodeUtf8(err) => eprintln!("Failed to decode utf-8 ({err})."),
        Error::UnknownSection(name) => eprintln!("Unknown section `{}`", name.escape_ascii()),
        Error::BadSection(name) => eprintln!("Bad section `{}`.", name.escape_ascii()),
        Error::IncompatibleGlobal => eprintln!("Incompatible global section."),
        Error::IncompatibleData => eprintln!("Incompatible data section."),
        Error::HashMismatch => eprintln!("Hash mismatch."),
        Error::NoMods => eprintln!("Cannot join mods if none are specified."),
        Error::ModsConflicts(name) => {
            eprintln!("Mods are in conflict with each other; failed to add `{name}` twice.")
        }
        Error::IO(error) => eprintln!("{error}."),
    }
    std::process::exit(1);
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => report_lexopt_error(e),
    };

    let Some(base_path) = args.base else {
        eprintln!("Base .csx path is unspecified.");
        std::process::exit(1);
    };

    let base = new_auto(base_path, None);

    let all_mods: Vec<_> = args
        .mods
        .into_iter()
        .map(|path| new_auto(path, Some(&base)))
        .collect();

    if !args.compact.is_empty() {
        if args.compact.len() > all_mods.len() {
            eprintln!(
                "Argument error: cannot compress more mods than specified (expected at most {}, got {}).",
                all_mods.len(),
                args.compact.len()
            );
            std::process::exit(1);
        }

        for (mods, modpath) in std::iter::zip(&all_mods, &args.compact) {
            let cco = compress_cco(&base, mods).rebuild();
            fs_write(modpath, cco);
        }

        if args.compact.len() < all_mods.len() {
            eprintln!(
                "Warning: only the first {} mods out of {} were saved.",
                args.compact.len(),
                all_mods.len()
            );
        }
    }

    if let Some(output_path) = &args.output {
        let patched = concat_and_apply_mods(&mut { base }, all_mods);
        fs_write(output_path, patched);
    }
}
