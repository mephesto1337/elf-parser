use nom;

pub mod types32;
pub use types32::*;

#[derive(Debug)]
pub struct Elf32 {
    pub header:     Elf32Header,
    pub segments:   Vec<Elf32Segment>,
    pub sections:   Vec<Elf32Section>,
}

pub fn parse_elf32(i: &[u8]) -> nom::IResult<&[u8], Elf32> {
    let header = parse_elf32_header(i)?.1;
    let ph_off = header.e_phoff as usize;
    let sh_off = header.e_shoff as usize;
    let segments = count!(&i[ph_off..], parse_elf32_segment, header.e_phnum as usize)?;
    let sections = count!(&i[sh_off..], parse_elf32_section, header.e_shnum as usize)?;
    let rest = if segments.0.len() > sections.0.len() { sections.0 } else { segments.0 };

    Ok((rest, Elf32 {
        header:     header,
        segments:   segments.1,
        sections:   sections.1
    }))
}
