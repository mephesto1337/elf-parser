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
pub enum SegmentType {
    /// Program header table entry unused
    Null = 0,

    /// Loadable program segment
    Load = 1,

    /// Dynamic linking information
    Dynamic = 2,

    /// Program interpreter
    Interp = 3,

    /// Auxiliary information
    Note = 4,

    /// Reserved
    Shlib = 5,

    /// Entry for header table itself
    Phdr = 6,

    /// Thread-local storage segment
    Tls = 7,

    /// Number of defined types
    Num = 8,

    /// Start of OS-specific
    Loos = 0x60000000,

    /// GCC .ehFrameHdr segment
    GnuEhFrame = 0x6474e550,

    /// Indicates stack executability
    GnuStack = 0x6474e551,

    /// Read-only after relocation
    GnuRelro = 0x6474e552,

    /// Sun Specific segment
    Sunwbss = 0x6ffffffa,

    /// Stack segment
    Sunwstack = 0x6ffffffb,

    /// End of OS-specific
    Hios = 0x6fffffff,

    /// Start of processor-specific
    Loproc = 0x70000000,

    /// End of processor-specific
    Hiproc = 0x7fffffff,
}

bitflags! {
    pub struct SegmentFlags: u32 {
        /// Segment is executable
        const EXECUTE = 1;

        /// Segment is writable
        const WRITE = 2;

        /// Segment is reable
        const READ = 4;
    }
}

#[derive(Debug, PartialEq)]
pub struct Elf64Segment {
    pub r#type: SegmentType,
    pub flags: SegmentFlags,
    pub offset: u64,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

parse_u32_enum!(parse_segment_type, SegmentType);

fn parse_segment_flags(input: &[u8]) -> IResult<&[u8], SegmentFlags> {
    map_opt(le_u32, SegmentFlags::from_bits)(input)
}

pub(crate) fn parse_elf64_segment(input: &[u8]) -> IResult<&[u8], Elf64Segment> {
    let (rest, (r#type, flags, offset, vaddr, paddr, filesz, memsz, align)) = tuple((
        parse_segment_type,
        parse_segment_flags,
        le_u64,
        parse_addr,
        parse_addr,
        le_u64,
        le_u64,
        le_u64,
    ))(input)?;

    Ok((
        rest,
        Elf64Segment {
            r#type,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
        },
    ))
}
