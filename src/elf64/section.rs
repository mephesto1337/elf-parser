use bitflags::bitflags;
use enum_primitive_derive::Primitive;
use nom::combinator::map_opt;
use nom::number::complete::{le_u32, le_u64};
use nom::sequence::tuple;
use nom::IResult;
use num_traits::FromPrimitive;

use crate::parse_u32_enum;
use crate::types::{parse_addr, Addr};

#[derive(Debug, PartialEq, Primitive)]
#[repr(u32)]
pub enum SectionType {
    /// Section header table entry unused
    Null = 0,

    /// Program data
    Progbits = 1,

    /// Symbol table
    Symtab = 2,

    /// String table
    Strtab = 3,

    /// Relocation entries with addends
    Rela = 4,

    /// Symbol hash table
    Hash = 5,

    /// Dynamic linking information
    Dynamic = 6,

    /// Notes
    Note = 7,

    /// Program space with no data (bss)
    Nobits = 8,

    /// Relocation entries, no addends
    Rel = 9,

    /// Reserved
    Shlib = 10,

    /// Dynamic linker symbol table
    Dynsym = 11,

    /// Array of constructors
    InitArray = 14,

    /// Array of destructors
    FiniArray = 15,

    /// Array of pre-constructors
    PreinitArray = 16,

    /// Section group
    Group = 17,

    /// Extended section indeces
    SymtabShndx = 18,

    /// Number of defined types.
    Num = 19,

    /// Start OS-specific.
    Loos = 0x60000000,

    /// Object attributes.
    GnuAttributes = 0x6ffffff5,

    /// GNU-style hash table.
    GnuHash = 0x6ffffff6,

    /// Prelink library list
    GnuLiblist = 0x6ffffff7,

    /// Checksum for DSO content.
    Checksum = 0x6ffffff8,

    /// Sun-specific low bound: 0x6ffffffa
    /// Sun-specific high bound: 0x6fffffff
    /// End OS-specific type
    Losunw = 0x6ffffffa,
    // SunwMove = 0x6ffffffa,
    SunwComdat = 0x6ffffffb,
    SunwSyminfo = 0x6ffffffc,

    /// Version definition section.
    GnuVerdef = 0x6ffffffd,

    /// Version needs section.
    GnuVerneed = 0x6ffffffe,

    /// Version symbol table.
    GnuVersym = 0x6fffffff,

    /// Start of processor-specific
    Loproc = 0x70000000,

    /// End of processor-specific
    Hiproc = 0x7fffffff,

    /// Start of application-specific
    Louser = 0x80000000,

    /// End of application-specific
    Hiuser = 0x8fffffff,
}

bitflags! {
    pub struct SectionFlags: u64 {
        /// Writable
        const WRITE = 1;
        /// Occupies memory during execution
        const ALLOC = 2;
        /// Executable
        const EXECINSTR = 4;
        /// Might be merged
        const MERGE = 16;
        /// Contains nul-terminated strings
        const STRINGS = 32;
        /// `sh_info' contains SHT index
        const INFO_LINK = 64;
        /// Preserve order after combining
        const LINK_ORDER = 128;
        /// Non-standard OS specific handling required
        const OS_NONCONFORMING = 256;
        /// Section is member of a group.
        const GROUP = 512;
        /// Section hold thread-local data.
        const TLS = 1024;
        /// Section with compressed data.
        const COMPRESSED = 2048;
        /// OS-specific.
        const MASKOS = 0x0FF00000;
        /// Processor-specific
        const MASKPROC = 0xF0000000;
        /// Special ordering requirement (Solaris).
        const ORDERED = 1073741824;
        /// Section is excluded unless referenced or allocated (Solaris).
        const EXCLUDE = 2147483648;
    }
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

parse_u32_enum!(parse_section_type, SectionType);

fn parse_section_flags(input: &[u8]) -> IResult<&[u8], SectionFlags> {
    map_opt(le_u64, SectionFlags::from_bits)(input)
}

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
