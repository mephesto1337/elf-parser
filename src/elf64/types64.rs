use nom;
use std::mem::size_of;

use header::{parse_elf_ident, ElfIdent};

type Elf64Half = u16;
type Elf64Word = u32;
type Elf64Xword = u64;
type Elf64Addr = u64;
type Elf64Off = u64;

#[derive(Debug, PartialEq)]
pub struct Elf64Header {
    pub e_ident: ElfIdent,
    pub e_type: Elf64Half,
    pub e_machine: Elf64Half,
    pub e_version: Elf64Word,
    pub e_entry: Elf64Addr,
    pub e_phoff: Elf64Off,
    pub e_shoff: Elf64Off,
    pub e_flags: Elf64Word,
    pub e_ehsize: Elf64Half,
    pub e_phentsize: Elf64Half,
    pub e_phnum: Elf64Half,
    pub e_shentsize: Elf64Half,
    pub e_shnum: Elf64Half,
    pub e_shstrndx: Elf64Half,
}

#[derive(Debug, PartialEq)]
pub struct Elf64Section {
    pub sh_name: Elf64Word,
    pub sh_type: Elf64Word,
    pub sh_flags: Elf64Xword,
    pub sh_addr: Elf64Addr,
    pub sh_offset: Elf64Off,
    pub sh_size: Elf64Xword,
    pub sh_link: Elf64Word,
    pub sh_info: Elf64Word,
    pub sh_addralign: Elf64Xword,
    pub sh_entsize: Elf64Xword,
}

#[derive(Debug, PartialEq)]
pub struct Elf64Segment {
    pub p_type: Elf64Word,
    pub p_flags: Elf64Word,
    pub p_offset: Elf64Off,
    pub p_vaddr: Elf64Addr,
    pub p_paddr: Elf64Addr,
    pub p_filesz: Elf64Xword,
    pub p_memsz: Elf64Xword,
    pub p_align: Elf64Xword,
}

#[inline(always)]
pub fn parse_elf64_half(i: &[u8]) -> nom::IResult<&[u8], Elf64Half> {
    nom::le_u16(i)
}

#[inline(always)]
pub fn parse_elf64_word(i: &[u8]) -> nom::IResult<&[u8], Elf64Word> {
    nom::le_u32(i)
}

#[inline(always)]
pub fn parse_elf64_xword(i: &[u8]) -> nom::IResult<&[u8], Elf64Xword> {
    nom::le_u64(i)
}

#[inline(always)]
pub fn parse_elf64_addr(i: &[u8]) -> nom::IResult<&[u8], Elf64Addr> {
    nom::le_u64(i)
}

#[inline(always)]
pub fn parse_elf64_off(i: &[u8]) -> nom::IResult<&[u8], Elf64Off> {
    nom::le_u64(i)
}

named!(
    parse_elf64_header_aux<Elf64Header>,
    do_parse!(
        _e_ident: parse_elf_ident
            >> _e_type: parse_elf64_half
            >> _e_machine: parse_elf64_half
            >> _e_version: parse_elf64_word
            >> _e_entry: parse_elf64_addr
            >> _e_phoff: parse_elf64_off
            >> _e_shoff: parse_elf64_off
            >> _e_flags: parse_elf64_word
            >> _e_ehsize:
                verify!(parse_elf64_half, |x: Elf64Half| (x as usize)
                    == size_of::<Elf64Header>())
            >> _e_phentsize:
                verify!(parse_elf64_half, |x: Elf64Half| (x as usize) == size_of::<
                    Elf64Segment,
                >(
                ))
            >> _e_phnum: parse_elf64_half
            >> _e_shentsize:
                verify!(parse_elf64_half, |x: Elf64Half| (x as usize) == size_of::<
                    Elf64Section,
                >(
                ))
            >> _e_shnum: parse_elf64_half
            >> _e_shstrndx: verify!(parse_elf64_half, |x: Elf64Half| x < _e_shnum)
            >> (Elf64Header {
                e_ident: _e_ident,
                e_type: _e_type,
                e_machine: _e_machine,
                e_version: _e_version,
                e_entry: _e_entry,
                e_phoff: _e_phoff,
                e_shoff: _e_shoff,
                e_flags: _e_flags,
                e_ehsize: _e_ehsize,
                e_phentsize: _e_phentsize,
                e_phnum: _e_phnum,
                e_shentsize: _e_shentsize,
                e_shnum: _e_shnum,
                e_shstrndx: _e_shstrndx,
            })
    )
);

pub fn parse_elf64_header(i: &[u8]) -> nom::IResult<&[u8], Elf64Header> {
    match parse_elf64_header_aux(i) {
        Ok((rest, hdr)) => {
            let ph_start = hdr.e_phoff as usize;
            let ph_end = ph_start + (hdr.e_phnum as usize) * (hdr.e_phentsize as usize);
            let sh_start = hdr.e_shoff as usize;
            let sh_end = sh_start + (hdr.e_shnum as usize) * (hdr.e_shentsize as usize);

            if ph_end > i.len() {
                Err(nom::Err::Error(error_position!(i, nom::ErrorKind::Verify)))
            } else if sh_end > i.len() {
                Err(nom::Err::Error(error_position!(i, nom::ErrorKind::Verify)))
            } else if ph_start < sh_start && ph_end > sh_start {
                Err(nom::Err::Error(error_position!(i, nom::ErrorKind::Verify)))
            } else if sh_start < ph_start && sh_end > ph_start {
                Err(nom::Err::Error(error_position!(i, nom::ErrorKind::Verify)))
            } else {
                Ok((rest, hdr))
            }
        }
        Err(e) => Err(e),
    }
}

named!(pub parse_elf64_segment<Elf64Segment>,
    do_parse!(
            _p_type:    parse_elf64_word
        >>  _p_flags:   parse_elf64_word
        >>  _p_offset:  parse_elf64_off
        >>  _p_vaddr:   parse_elf64_addr
        >>  _p_paddr:   parse_elf64_addr
        >>  _p_filesz:  parse_elf64_xword
        >>  _p_memsz:   parse_elf64_xword
        >>  _p_align:   parse_elf64_xword
        >>  ( Elf64Segment {
            p_type:     _p_type,
            p_flags:    _p_flags,
            p_offset:   _p_offset,
            p_vaddr:    _p_vaddr,
            p_paddr:    _p_paddr,
            p_filesz:   _p_filesz,
            p_memsz:    _p_memsz,
            p_align:    _p_align,
        })
    )
);

named!(pub parse_elf64_section<Elf64Section>,
    do_parse!(
            _sh_name:       parse_elf64_word
        >>  _sh_type:       parse_elf64_word
        >>  _sh_flags:      parse_elf64_xword
        >>  _sh_addr:       parse_elf64_addr
        >>  _sh_offset:     parse_elf64_off
        >>  _sh_size:       parse_elf64_xword
        >>  _sh_link:       parse_elf64_word
        >>  _sh_info:       parse_elf64_word
        >>  _sh_addralign:  parse_elf64_xword
        >>  _sh_entsize:    parse_elf64_xword
        >>  ( Elf64Section {
            sh_name:       _sh_name,
            sh_type:       _sh_type,
            sh_flags:      _sh_flags,
            sh_addr:       _sh_addr,
            sh_offset:     _sh_offset,
            sh_size:       _sh_size,
            sh_link:       _sh_link,
            sh_info:       _sh_info,
            sh_addralign:  _sh_addralign,
            sh_entsize:    _sh_entsize,
        })
    )
);
