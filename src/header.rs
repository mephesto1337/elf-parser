use enum_primitive_derive::Primitive;
use nom::bytes::complete::{tag, take};
use nom::number::complete::le_u8;
use nom::sequence::tuple;
use nom::IResult;
use num_traits::FromPrimitive;

use crate::{parse_u16_enum, parse_u8_enum};

#[derive(Debug, PartialEq, Primitive)]
#[repr(u8)]
pub enum ElfClass {
    /// Invalid class
    None = 0,
    /// 32-bit objects
    _32 = 1,
    /// 64-bit objects
    _64 = 2,
}

#[derive(Debug, PartialEq, Primitive)]
#[repr(u8)]
pub enum ElfData {
    /// Invalid data encoding
    None = 0,
    /// 2's complement, little endian
    _2Lsb = 1,
    /// 2's complement, big endian
    _2Msb = 2,
}

#[derive(Debug, PartialEq, Primitive)]
#[repr(u8)]
pub enum ElfOSAbi {
    /// UNIX System V ABI
    Sysv = 0,
    /// HP-UX
    Hpux = 1,
    /// NetBSD.  
    Netbsd = 2,
    /// Object uses GNU ELF extensions.  
    Gnu = 3,
    /// Sun Solaris.  
    Solaris = 6,
    /// IBM AIX.  
    Aix = 7,
    /// SGI Irix.  
    Irix = 8,
    /// FreeBSD.  
    Freebsd = 9,
    /// Compaq TRU64 UNIX.  
    Tru64 = 10,
    /// Novell Modesto.  
    Modesto = 11,
    /// OpenBSD.  
    Openbsd = 12,
    /// ARM EABI
    ArmAeabi = 64,
    /// ARM
    Arm = 97,
    /// Standalone (embedded) application
    Standalone = 255,
}

#[derive(Debug, PartialEq)]
pub struct ElfIdent {
    /// File class
    pub class: ElfClass,

    /// Data encoding byte index
    pub data: ElfData,

    /// Value must be EV_CURRENT
    pub abi_version: u8,

    /// OS ABI identification
    pub osabi: ElfOSAbi,
}

parse_u8_enum!(parse_elf_class, ElfClass);
parse_u8_enum!(parse_elf_data, ElfData);
parse_u16_enum!(parse_elf_osabi, ElfOSAbi);

pub fn parse_elf_ident(input: &[u8]) -> IResult<&[u8], ElfIdent> {
    let (rest, (_tag, class, data, abi_version, osabi, _padding)) = tuple((
        tag(b"\x7fELF"),
        parse_elf_class,
        parse_elf_data,
        le_u8,
        parse_elf_osabi,
        take(7usize),
    ))(input)?;

    Ok((
        rest,
        ElfIdent {
            class,
            data,
            abi_version,
            osabi,
        },
    ))
}
