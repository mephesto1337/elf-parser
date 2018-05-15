use nom;
use exe;

pub mod types64;
pub use types64::*;

use libc::{size_t, uint8_t, c_void};

#[derive(Debug)]
pub struct Elf64<'a> {
    pub data:       &'a [u8],
    pub header:     Elf64Header,
    pub segments:   Vec<Elf64Segment>,
    pub sections:   Vec<Elf64Section>,
}

pub fn parse_elf64<'a>(i: &'a [u8]) -> nom::IResult<&'a [u8], Elf64<'a>> {
    let header = parse_elf64_header(i)?.1;
    let ph_off = header.e_phoff as usize;
    let sh_off = header.e_shoff as usize;
    let segments = count!(&i[ph_off..], parse_elf64_segment, header.e_phnum as usize)?;
    let sections = count!(&i[sh_off..], parse_elf64_section, header.e_shnum as usize)?;
    let rest = if segments.0.len() > sections.0.len() { sections.0 } else { segments.0 };

    Ok((rest, Elf64 {
        data:       i,
        header:     header,
        segments:   segments.1,
        sections:   sections.1
    }))
}

impl exe::Section for Elf64Section {
    fn get_flags(&self) -> u32 {
        // Always readable
        let mut flags = 4u32;

        // Writable
        if self.sh_flags & 1u64 != 0 {
            flags |= 2;
        }
        // Executable
        if self.sh_flags & 4u64 != 0 {
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

impl<'a> exe::Exe<'a> for Elf64<'a> {
    type Item = Elf64Section;

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
        match parse_elf64(i) {
            Ok((_, e)) => Some(e),
            Err(_) => None
        }
    }

    fn get_data(&self, start: usize, len: usize) -> & [u8] {
        &self.data[start .. (start + len)]
    }
}


#[no_mangle]
pub extern fn rs_elf64_parse<'a>(i: *const uint8_t, len: size_t) -> *const c_void {
    let buf = unsafe { ::std::slice::from_raw_parts(i as *const u8, len) };

    match parse_elf64(buf) {
        Ok((_, e64)) => Box::into_raw(Box::new(e64)) as *const c_void,
        Err(_) => ::std::ptr::null::<c_void>()
    }
}

generate_c_api!(Elf64Section, Elf64<'a>,
    rs_elf64_get_flags,
    rs_elf64_get_offset,
    rs_elf64_get_size,
    rs_elf64_get_number_of_sections,
    rs_elf64_get_section_at,
    rs_elf64_get_section_name_at,
    rs_elf64_get_data,
    rs_elf64_free_exe
);
