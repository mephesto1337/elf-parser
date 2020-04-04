use nom::combinator::verify;
use nom::number::complete::{le_u16, le_u32, le_u64};
use nom::sequence::tuple;
use nom::IResult;

use crate::header::{parse_elf_ident, ElfIdent};
use crate::types::{
    parse_addr, parse_elf_machine, parse_elf_type, parse_elf_version, Addr, ElfMachine, ElfType,
    ElfVersion,
};

#[derive(Debug, PartialEq)]
pub struct Elf64Header {
    pub ident: ElfIdent,
    pub r#type: ElfType,
    pub machine: ElfMachine,
    pub version: ElfVersion,
    pub entry: Addr,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

fn parse_elf64_header_aux(input: &[u8]) -> IResult<&[u8], Elf64Header> {
    let (
        rest,
        (
            ident,
            r#type,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        ),
    ) = tuple((
        parse_elf_ident,
        parse_elf_type,
        parse_elf_machine,
        parse_elf_version,
        parse_addr,
        verify(le_u64, |phoff| (*phoff as usize) < input.len()),
        verify(le_u64, |shoff| (*shoff as usize) < input.len()),
        le_u32,
        verify(le_u16, |ehsize| ehsize == &64),
        verify(le_u16, |phentsize| phentsize == &56),
        le_u16,
        verify(le_u16, |shentsize| shentsize == &64),
        le_u16,
        le_u16,
    ))(input)?;

    Ok((
        rest,
        Elf64Header {
            ident,
            r#type,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        },
    ))
}

pub fn parse_elf64_header(input: &[u8]) -> IResult<&[u8], Elf64Header> {
    match parse_elf64_header_aux(input) {
        Ok((rest, hdr)) => {
            let ph_start = hdr.phoff as usize;
            let ph_end = ph_start + (hdr.phnum as usize) * (hdr.phentsize as usize);
            let sh_start = hdr.shoff as usize;
            let sh_end = sh_start + (hdr.shnum as usize) * (hdr.shentsize as usize);

            if ph_end > input.len() {
                return nom::error::context("Program headers goes over the end", |i| {
                    Err(nom::Err::Error((i, nom::error::ErrorKind::TooLarge)))
                })(input);
            } else if sh_end > input.len() {
                return nom::error::context("Section headers goes over the end", |i| {
                    Err(nom::Err::Error((i, nom::error::ErrorKind::TooLarge)))
                })(input);
            } else if ph_start < sh_start && ph_end > sh_start {
                return nom::error::context(
                    "Section headers and program headers shared a region",
                    |i| Err(nom::Err::Error((i, nom::error::ErrorKind::TooLarge))),
                )(input);
            } else if sh_start < ph_start && sh_end > ph_start {
                return nom::error::context(
                    "Section headers and program headers shared a region",
                    |i| Err(nom::Err::Error((i, nom::error::ErrorKind::TooLarge))),
                )(input);
            } else {
                Ok((rest, hdr))
            }
        }
        Err(e) => Err(e),
    }
}
