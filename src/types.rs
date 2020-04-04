use bitflags::bitflags;
use enum_primitive_derive::Primitive;
use nom::combinator::map_opt;
use nom::number::complete::le_u64;
use nom::IResult;
use num_traits::FromPrimitive;

use crate::{parse_u16_enum, parse_u32_enum};

#[derive(Debug, PartialEq, Primitive)]
#[repr(u32)]
pub enum ElfVersion {
    /// Invalid ELF version
    None = 0,
    /// Current ELF version
    Current = 1,
}

#[derive(Debug, PartialEq, Primitive)]
#[repr(u16)]
pub enum ElfType {
    /// No file type
    None = 0,
    /// Relocatable file
    Rel = 1,
    /// Executable file
    Exec = 2,
    /// Shared object file
    Dyn = 3,
    /// Core file
    Core = 4,
    /// Number of defined types
    Num = 5,
    /// OS-specific range start
    Loos = 0xfe00,
    /// OS-specific range end
    Hios = 0xfeff,
    /// Processor-specific range start
    Loproc = 0xff00,
    /// Processor-specific range end
    Hiproc = 0xffff,
}

#[derive(Debug, PartialEq, Primitive)]
#[repr(u16)]
pub enum ElfMachine {
    /// No machine
    None = 0,
    /// AT&T WE 32100
    M32 = 1,
    /// SUN SPARC
    Sparc = 2,
    /// Intel 80386
    _386 = 3,
    /// Motorola m68k family
    _68k = 4,
    /// Motorola m88k family
    _88k = 5,
    /// Intel MCU
    Iamcu = 6,
    /// Intel 80860
    _860 = 7,
    /// MIPS R3000 big-endian
    Mips = 8,
    /// IBM System/370
    S370 = 9,
    /// MIPS R3000 little-endian
    MipsRs3Le = 10,
    /// HPPA
    Parisc = 15,
    /// Fujitsu VPP500
    Vpp500 = 17,
    /// Sun's "v8plus"
    Sparc32plus = 18,
    /// Intel 80960
    _960 = 19,
    /// PowerPC
    Ppc = 20,
    /// PowerPC 64-bit
    Ppc64 = 21,
    /// IBM S390
    S390 = 22,
    /// IBM SPU/SPC
    Spu = 23,
    /// NEC V800 series
    V800 = 36,
    /// Fujitsu FR20
    Fr20 = 37,
    /// TRW RH-32
    Rh32 = 38,
    /// Motorola RCE
    Rce = 39,
    /// ARM
    Arm = 40,
    /// Digital Alpha
    FakeAlpha = 41,
    /// Hitachi SH
    Sh = 42,
    /// SPARC v9 64-bit
    Sparcv9 = 43,
    /// Siemens Tricore
    Tricore = 44,
    /// Argonaut RISC Core
    Arc = 45,
    /// Hitachi H8/300
    H8300 = 46,
    /// Hitachi H8/300H
    H8300h = 47,
    /// Hitachi H8S
    H8s = 48,
    /// Hitachi H8/500
    H8500 = 49,
    /// Intel Merced
    Ia64 = 50,
    /// Stanford MIPS-X
    MipsX = 51,
    /// Motorola Coldfire
    Coldfire = 52,
    /// Motorola M68HC12
    _68hc12 = 53,
    /// Fujitsu MMA Multimedia Accelerator
    Mma = 54,
    /// Siemens PCP
    Pcp = 55,
    /// Sony nCPU embeeded RISC
    Ncpu = 56,
    /// Denso NDR1 microprocessor
    Ndr1 = 57,
    /// Motorola Start*Core processor
    Starcore = 58,
    /// Toyota ME16 processor
    Me16 = 59,
    /// STMicroelectronic ST100 processor
    St100 = 60,
    /// Advanced Logic Corp. Tinyj emb.fam
    Tinyj = 61,
    /// AMD x86-64 architecture
    X8664 = 62,
    /// Sony DSP Processor
    Pdsp = 63,
    /// Digital PDP-10
    Pdp10 = 64,
    /// Digital PDP-11
    Pdp11 = 65,
    /// Siemens FX66 microcontroller
    Fx66 = 66,
    /// STMicroelectronics ST9+ 8/16 mc
    St9plus = 67,
    /// STmicroelectronics ST7 8 bit mc
    St7 = 68,
    /// Motorola MC68HC16 microcontroller
    _68hc16 = 69,
    /// Motorola MC68HC11 microcontroller
    _68hc11 = 70,
    /// Motorola MC68HC08 microcontroller
    _68hc08 = 71,
    /// Motorola MC68HC05 microcontroller
    _68hc05 = 72,
    /// Silicon Graphics SVx
    Svx = 73,
    /// STMicroelectronics ST19 8 bit mc
    St19 = 74,
    /// Digital VAX
    Vax = 75,
    /// Axis Communications 32-bit emb.proc
    Cris = 76,
    /// Infineon Technologies 32-bit emb.proc
    Javelin = 77,
    /// Element 14 64-bit DSP Processor
    Firepath = 78,
    /// LSI Logic 16-bit DSP Processor
    Zsp = 79,
    /// Donald Knuth's educational 64-bit proc
    Mmix = 80,
    /// Harvard University machine-independent object files
    Huany = 81,
    /// SiTera Prism
    Prism = 82,
    /// Atmel AVR 8-bit microcontroller
    Avr = 83,
    /// Fujitsu FR30
    Fr30 = 84,
    /// Mitsubishi D10V
    D10v = 85,
    /// Mitsubishi D30V
    D30v = 86,
    /// NEC v850
    V850 = 87,
    /// Mitsubishi M32R
    M32r = 88,
    /// Matsushita MN10300
    Mn10300 = 89,
    /// Matsushita MN10200
    Mn10200 = 90,
    /// picoJava
    Pj = 91,
    /// OpenRISC 32-bit embedded processor
    Openrisc = 92,
    /// ARC International ARCompact
    ArcCompact = 93,
    /// Tensilica Xtensa Architecture
    Xtensa = 94,
    /// Alphamosaic VideoCore
    Videocore = 95,
    /// Thompson Multimedia General Purpose Proc
    TmmGpp = 96,
    /// National Semi. 32000
    Ns32k = 97,
    /// Tenor Network TPC
    Tpc = 98,
    /// Trebia SNP 1000
    Snp1k = 99,
    /// STMicroelectronics ST200
    St200 = 100,
    /// Ubicom IP2xxx
    Ip2k = 101,
    /// MAX processor
    Max = 102,
    /// National Semi. CompactRISC
    Cr = 103,
    /// Fujitsu F2MC16
    F2mc16 = 104,
    /// Texas Instruments msp430
    Msp430 = 105,
    /// Analog Devices Blackfin DSP
    Blackfin = 106,
    /// Seiko Epson S1C33 family
    SeC33 = 107,
    /// Sharp embedded microprocessor
    Sep = 108,
    /// Arca RISC
    Arca = 109,
    /// PKU-Unity & MPRC Peking Uni. mc series
    Unicore = 110,
    /// eXcess configurable cpu
    Excess = 111,
    /// Icera Semi. Deep Execution Processor
    Dxp = 112,
    /// Altera Nios II
    AlteraNios2 = 113,
    /// National Semi. CompactRISC CRX
    Crx = 114,
    /// Motorola XGATE
    Xgate = 115,
    /// Infineon C16x/XC16x
    C166 = 116,
    /// Renesas M16C
    M16c = 117,
    /// Microchip Technology dsPIC30F
    Dspic30f = 118,
    /// Freescale Communication Engine RISC
    Ce = 119,
    /// Renesas M32C
    M32c = 120,
    /// Altium TSK3000
    Tsk3000 = 131,
    /// Freescale RS08
    Rs08 = 132,
    /// Analog Devices SHARC family
    Sharc = 133,
    /// Cyan Technology eCOG2
    Ecog2 = 134,
    /// Sunplus S+core7 RISC
    Score7 = 135,
    /// New Japan Radio (NJR) 24-bit DSP
    Dsp24 = 136,
    /// Broadcom VideoCore III
    Videocore3 = 137,
    /// RISC for Lattice FPGA
    Latticemico32 = 138,
    /// Seiko Epson C17
    SeC17 = 139,
    /// Texas Instruments TMS320C6000 DSP
    TiC6000 = 140,
    /// Texas Instruments TMS320C2000 DSP
    TiC2000 = 141,
    /// Texas Instruments TMS320C55x DSP
    TiC5500 = 142,
    /// Texas Instruments App. Specific RISC
    TiArp32 = 143,
    /// Texas Instruments Prog. Realtime Unit
    TiPru = 144,
    /* reserved 145-159 */
    /// STMicroelectronics 64bit VLIW DSP
    MmdspPlus = 160,
    /// Cypress M8C
    CypressM8c = 161,
    /// Renesas R32C
    R32c = 162,
    /// NXP Semi. TriMedia
    Trimedia = 163,
    /// QUALCOMM DSP6
    Qdsp6 = 164,
    /// Intel 8051 and variants
    _8051 = 165,
    /// STMicroelectronics STxP7x
    Stxp7x = 166,
    /// Andes Tech. compact code emb. RISC
    Nds32 = 167,
    /// Cyan Technology eCOG1X
    Ecog1x = 168,
    /// Dallas Semi. MAXQ30 mc
    Maxq30 = 169,
    /// New Japan Radio (NJR) 16-bit DSP
    Ximo16 = 170,
    /// M2000 Reconfigurable RISC
    Manik = 171,
    /// Cray NV2 vector architecture
    Craynv2 = 172,
    /// Renesas RX
    Rx = 173,
    /// Imagination Tech. META
    Metag = 174,
    /// MCST Elbrus
    McstElbrus = 175,
    /// Cyan Technology eCOG16
    Ecog16 = 176,
    /// National Semi. CompactRISC CR16
    Cr16 = 177,
    /// Freescale Extended Time Processing Unit
    Etpu = 178,
    /// Infineon Tech. SLE9X
    Sle9x = 179,
    /// Intel L10M
    L10m = 180,
    /// Intel K10M
    K10m = 181,
    /// ARM AARCH64
    Aarch64 = 183,
    /// Amtel 32-bit microprocessor
    Avr32 = 185,
    /// STMicroelectronics STM8
    Stm8 = 186,
    /// Tileta TILE64
    Tile64 = 187,
    /// Tilera TILEPro
    Tilepro = 188,
    /// Xilinx MicroBlaze
    Microblaze = 189,
    /// NVIDIA CUDA
    Cuda = 190,
    /// Tilera TILE-Gx
    Tilegx = 191,
    /// CloudShield
    Cloudshield = 192,
    /// KIPO-KAIST Core-A 1st gen.
    Corea1st = 193,
    /// KIPO-KAIST Core-A 2nd gen.
    Corea2nd = 194,
    /// Synopsys ARCompact V2
    ArcCompact2 = 195,
    /// Open8 RISC
    Open8 = 196,
    /// Renesas RL78
    Rl78 = 197,
    /// Broadcom VideoCore V
    Videocore5 = 198,
    /// Renesas 78KOR
    _78kor = 199,
    /// Freescale 56800EX DSC
    _56800ex = 200,
    /// Beyond BA1
    Ba1 = 201,
    /// Beyond BA2
    Ba2 = 202,
    /// XMOS xCORE
    Xcore = 203,
    /// Microchip 8-bit PIC(r)
    MchpPic = 204,
    /// KM211 KM32
    Km32 = 210,
    /// KM211 KMX32
    Kmx32 = 211,
    /// KM211 KMX16
    Emx16 = 212,
    /// KM211 KMX8
    Emx8 = 213,
    /// KM211 KVARC
    Kvarc = 214,
    /// Paneve CDP
    Cdp = 215,
    /// Cognitive Smart Memory Processor
    Coge = 216,
    /// Bluechip CoolEngine
    Cool = 217,
    /// Nanoradio Optimized RISC
    Norc = 218,
    /// CSR Kalimba
    CsrKalimba = 219,
    /// Zilog Z80
    Z80 = 220,
    /// Controls and Data Services VISIUMcore
    Visium = 221,
    /// FTDI Chip FT32
    Ft32 = 222,
    /// Moxie processor
    Moxie = 223,
    /// AMD GPU
    Amdgpu = 224,
    /// RISC-V
    Riscv = 243,
    /// Linux BPF -- in-kernel virtual machine
    Bpf = 247,
    /// C-SKY
    Csky = 252,
}

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

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub struct Addr(u64);

parse_u32_enum!(pub(crate) parse_elf_version, ElfVersion);
parse_u16_enum!(pub(crate) parse_elf_type, ElfType);
parse_u16_enum!(pub(crate) parse_elf_machine, ElfMachine);
parse_u32_enum!(pub(crate) parse_section_type, SectionType);

pub(crate) fn parse_section_flags(input: &[u8]) -> IResult<&[u8], SectionFlags> {
    map_opt(le_u64, SectionFlags::from_bits)(input)
}

#[inline]
pub(crate) fn parse_addr(input: &[u8]) -> IResult<&[u8], Addr> {
    let (rest, addr) = le_u64(input)?;

    Ok((rest, Addr(addr)))
}
