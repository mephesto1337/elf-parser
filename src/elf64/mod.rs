// use exe;
use nom::multi::count;
use nom::IResult;

pub mod header;
pub mod section;
pub mod segment;

use header::{parse_elf64_header, Elf64Header};
use section::{parse_elf64_section, Elf64Section};
use segment::{parse_elf64_segment, Elf64Segment};

#[derive(Debug)]
pub struct Elf64<'a> {
    pub data: &'a [u8],
    pub header: Elf64Header,
    pub segments: Vec<Elf64Segment>,
    pub sections: Vec<Elf64Section>,
}

pub fn parse_elf64<'a>(input: &'a [u8]) -> IResult<&'a [u8], Elf64<'a>> {
    let (_, header) = parse_elf64_header(input)?;

    let ph_off = header.phoff as usize;
    let sh_off = header.shoff as usize;

    let (seg_rest, segments) = count(parse_elf64_segment, header.phnum as usize)(&input[ph_off..])?;
    let (sec_rest, sections) = count(parse_elf64_section, header.shnum as usize)(&input[sh_off..])?;
    let rest = if seg_rest.len() > sec_rest.len() {
        sec_rest
    } else {
        seg_rest
    };

    Ok((
        rest,
        Elf64 {
            data: input,
            header,
            segments,
            sections,
        },
    ))
}

// impl exe::Section for Elf64Section {
//     fn get_flags(&self) -> u32 {
//         // Always readable
//         let mut flags = 4u32;
//
//         // Writable
//         if self.sh_flags & 1u64 != 0 {
//             flags |= 2;
//         }
//         // Executable
//         if self.sh_flags & 4u64 != 0 {
//             flags |= 1;
//         }
//
//         flags
//     }
//
//     fn get_offset(&self) -> usize {
//         self.sh_offset as usize
//     }
//
//     fn get_size(&self) -> usize {
//         self.sh_size as usize
//     }
// }
//
// impl<'a> exe::Exe<'a> for Elf64<'a> {
//     type Item = Elf64Section;
//
//     fn get_number_of_sections(&self) -> usize {
//         self.header.e_shnum as usize
//     }
//
//     fn get_section_at(&self, idx: usize) -> Option<&Self::Item> {
//         self.sections.iter().nth(idx)
//     }
//
//     fn get_section_name_at(&self, idx: usize) -> Option<&str> {
//         let strndx = match self.sections.iter().nth(self.header.e_shstrndx as usize) {
//             Some(s) => s,
//             None => {
//                 return None;
//             }
//         };
//         let s = match self.sections.iter().nth(idx) {
//             Some(x) => x,
//             None => {
//                 return None;
//             }
//         };
//
//         let off = s.sh_name as usize + strndx.sh_offset as usize;
//         match self.data[off..]
//             .iter()
//             .enumerate()
//             .filter(|(_, &c)| c == 0)
//             .map(|(i, _)| i)
//             .nth(0)
//         {
//             Some(size) => ::std::str::from_utf8(&self.data[off..off + size]).ok(),
//             None => None,
//         }
//     }
//
//     fn parse(i: &'a [u8]) -> Option<Self> {
//         match parse_elf64(i) {
//             Ok((_, e)) => Some(e),
//             Err(_) => None,
//         }
//     }
//
//     fn get_info(&self) -> exe::Info {
//         exe::Info {
//             os: String::from("linux"),
//             arch: String::from("x86"),
//             bits: 64usize,
//         }
//     }
//
//     fn get_data(&self, start: usize, len: usize) -> &[u8] {
//         &self.data[start..(start + len)]
//     }
// }
//
// #[no_mangle]
// pub extern "C" fn rs_elf64_parse<'a>(i: *const uint8_t, len: size_t) -> *const c_void {
//     let buf = unsafe { ::std::slice::from_raw_parts(i as *const u8, len) };
//
//     match parse_elf64(buf) {
//         Ok((_, e64)) => Box::into_raw(Box::new(e64)) as *const c_void,
//         Err(_) => ::std::ptr::null::<c_void>(),
//     }
// }
//
// generate_c_api!(
//     Elf64<'a>,
//     rs_elf64_get_info,
//     rs_elf64_free_info,
//     rs_elf64_get_number_of_sections,
//     rs_elf64_get_section_at,
//     rs_elf64_get_data,
//     rs_elf64_free_section,
//     rs_elf64_free_exe
// );
