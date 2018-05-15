use nom;
use exe;

pub mod types32;
pub use types32::*;

use libc::{size_t, uint8_t, c_void};

#[derive(Debug)]
pub struct Elf32<'a> {
    pub data:       &'a [u8],
    pub header:     Elf32Header,
    pub segments:   Vec<Elf32Segment>,
    pub sections:   Vec<Elf32Section>,
}

pub fn parse_elf32<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], Elf32<'a>> {
    let header = parse_elf32_header(i)?.1;
    let ph_off = header.e_phoff as usize;
    let sh_off = header.e_shoff as usize;
    let segments = count!(&i[ph_off..], parse_elf32_segment, header.e_phnum as usize)?;
    let sections = count!(&i[sh_off..], parse_elf32_section, header.e_shnum as usize)?;
    let rest = if segments.0.len() > sections.0.len() { sections.0 } else { segments.0 };

    Ok((rest, Elf32 {
        data:       i,
        header:     header,
        segments:   segments.1,
        sections:   sections.1
    }))
}

impl exe::Section for Elf32Section {
    fn get_flags(&self) -> u32 {
        // Always readable
        let mut flags = 4u32;

        // Writable
        if self.sh_flags & 1u32 != 0 {
            flags |= 2;
        }
        // Executable
        if self.sh_flags & 4u32 != 0 {
            flags |= 1;
        }

        flags
    }

    fn get_offset(&self) -> usize {
        self.sh_offset as usize
    }

    fn get_size(&self) -> usize {
        self.sh_size as usize
    }
}

impl<'a> exe::Exe<'a> for Elf32<'a> {
    type Item = Elf32Section;

    fn get_number_of_sections(&self) -> usize {
        self.header.e_shnum as usize
    }

    fn get_section_at(&self, idx: usize) -> Option<&Self::Item> {
        self.sections.iter().nth(idx)
    }

    fn get_section_name_at(&self, idx: usize) -> Option<&str> {
        let strndx = match self.sections.iter().nth(self.header.e_shstrndx as usize) {
            Some(s) => s,
            None => { return None; }
        };
        let s = match self.sections.iter().nth(idx) {
            Some(x) => x,
            None => { return None; }
        };

        let off = s.sh_name as usize + strndx.sh_offset as usize;
        match self.data[off..].iter().enumerate().filter(|(_, &c)| c == 0).map(|(i, _)| i).nth(0) {
            Some(size) => ::std::str::from_utf8(&self.data[off..off + size]).ok(),
            None => None
        }
    }


    fn parse(i: &'a [u8]) -> Option<Self> {
        match parse_elf32(i) {
            Ok((_, e)) => Some(e),
            Err(_) => None
        }
    }

    fn get_data(&self, start: usize, len: usize) -> & [u8] {
        &self.data[start .. (start + len)]
    }
}

#[no_mangle]
pub extern fn rs_elf32_parse<'a>(i: *const uint8_t, len: size_t) -> *const c_void {
    let buf = unsafe { ::std::slice::from_raw_parts(i as *const u8, len) };

    match parse_elf32(buf) {
        Ok((_, e32)) => Box::into_raw(Box::new(e32)) as *const c_void,
        Err(_) => ::std::ptr::null::<c_void>()
    }
}

generate_c_api!(Elf32Section, Elf32<'a>,
    rs_elf32_get_flags,
    rs_elf32_get_offset,
    rs_elf32_get_size,
    rs_elf32_get_number_of_sections,
    rs_elf32_get_section_at,
    rs_elf32_get_section_name_at,
    rs_elf32_get_data,
    rs_elf32_free_exe
);
