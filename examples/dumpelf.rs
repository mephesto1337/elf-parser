extern crate clap;
extern crate elf;
#[macro_use] extern crate failure;
extern crate nom;

use clap::{App, Arg};
use elf::*;
use std::convert::From;
use std::fs;
use std::io::{self, Read};

#[derive(Fail, Debug)]
enum Error {
    #[fail(display = "Parse error : {}", _0)]
    ParseError(String),

    #[fail(display = "IO error : {}", _0)]
    IOError(io::Error),

    #[fail(display = "Args error : {}", _0)]
    ArgsError(clap::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IOError(e)
    }
}

impl From<clap::Error> for Error {
    fn from(e: clap::Error) -> Error {
        Error::ArgsError(e)
    }
}


fn run() -> Result<(), Error> {
    let args = App::new("dumpelf")
        .version("1.0")
        .author("Thomas WACHE")
        .arg(
            Arg::with_name("elf").index(1)
        )
        .get_matches_safe()?;
    if let Some(elffilename) = args.value_of("elf") {
        let mut buf: Vec<u8> = Vec::new();
        let mut file = fs::File::open(elffilename)?;
        let elffilesize = file.read_to_end(&mut buf)?;

        println!("Loaded {} bytes from {}", elffilesize, elffilename);

        let (_, hdr) = parse_elf_ident(&buf.as_slice()).unwrap();
        match hdr.class {
            ElfClass::Class32 => {
                let (_, elf32) = parse_elf32(&buf.as_slice()).unwrap();
                println!("ELF32 = {:#?}", elf32);
            },
            ElfClass::Class64 => {
                let (_, elf64) = parse_elf64(&buf.as_slice()).unwrap();
                println!("ELF64 = {:#?}", elf64);
            }
        }
        Ok(())
    } else {
        Err(Error::ArgsError(clap::Error {
            message:    String::from("elf argument must be privided"),
            kind:       clap::ErrorKind::EmptyValue,
            info:       None
        }))
    }
}

fn main() {
    match run() {
        Ok(()) => {},
        Err(e) => println!("{}", e)
    }
}
