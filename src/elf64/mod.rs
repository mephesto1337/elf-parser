use nom;

pub mod types64;
pub use types64::*;

#[derive(Debug)]
pub struct Elf64 {
    pub header:     Elf64Header,
    pub segments:   Vec<Elf64Segment>,
    pub sections:   Vec<Elf64Section>,
}

pub fn parse_elf64(i: &[u8]) -> nom::IResult<&[u8], Elf64> {
    let header = parse_elf64_header(i)?.1;
    let ph_off = header.e_phoff as usize;
    let sh_off = header.e_shoff as usize;
    let segments = count!(&i[ph_off..], parse_elf64_segment, header.e_phnum as usize)?;
    let sections = count!(&i[sh_off..], parse_elf64_section, header.e_shnum as usize)?;
    let rest = if segments.0.len() > sections.0.len() { sections.0 } else { segments.0 };

    Ok((rest, Elf64 {
        header:     header,
        segments:   segments.1,
        sections:   sections.1
    }))
}
