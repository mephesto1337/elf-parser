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
    let args = App::new("readelf")
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

        println!("sizeof(ElfIdent) = {}", ::std::mem::size_of::<ElfIdent>());
        match parse_elf64(buf.as_slice()) {
            Ok((_rest, elf64)) => {
                println!("ELF = {:#?}", elf64);
                Ok(())
            },
            Err(e) => Err(Error::ParseError(format!("{:?}", e.into_error_kind()))),
        }
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
