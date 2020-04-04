use nom::combinator::verify;
use nom::number::complete::{le_u16, le_u32, le_u64};
use nom::sequence::tuple;
use nom::IResult;

use crate::header::{parse_elf_ident, ElfIdent};
use crate::types::{
    parse_addr, parse_elf_machine, parse_elf_type, parse_elf_version, parse_section_flags,
    parse_section_type, Addr, ElfMachine, ElfType, ElfVersion, SectionFlags, SectionType,
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

#[derive(Debug, PartialEq)]
pub struct Elf64Section {
    pub name: u32,
    pub r#type: SectionType,
    pub flags: SectionFlags,
    pub addr: Addr,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

#[derive(Debug, PartialEq)]
pub struct Elf64Segment {
    pub r#type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
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

// named!(pub parse_elf64_segment<Elf64Segment>,
//     do_parse!(
//             _p_type:    parse_elf64_word
//         >>  _p_flags:   parse_elf64_word
//         >>  _p_offset:  parse_elf64_off
//         >>  _p_vaddr:   parse_elf64_addr
//         >>  _p_paddr:   parse_elf64_addr
//         >>  _p_filesz:  parse_elf64_xword
//         >>  _p_memsz:   parse_elf64_xword
//         >>  _p_align:   parse_elf64_xword
//         >>  ( Elf64Segment {
//             p_type:     _p_type,
//             p_flags:    _p_flags,
//             p_offset:   _p_offset,
//             p_vaddr:    _p_vaddr,
//             p_paddr:    _p_paddr,
//             p_filesz:   _p_filesz,
//             p_memsz:    _p_memsz,
//             p_align:    _p_align,
//         })
//     )
// );

pub fn parse_elf64_section(input: &[u8]) -> IResult<&[u8], Elf64Section> {
    let (rest, (name, r#type, flags, addr, offset, size, link, info, addralign, entsize)) =
        tuple((
            le_u32,
            parse_section_type,
            parse_section_flags,
            parse_addr,
            le_u64,
            le_u64,
            le_u32,
            le_u32,
            le_u64,
            le_u64,
        ))(input)?;

    Ok((
        rest,
        Elf64Section {
            name,
            r#type,
            flags,
            addr,
            offset,
            size,
            link,
            info,
            addralign,
            entsize,
        },
    ))
}
