use nom;
use enum_primitive::FromPrimitive;


enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
enum ElfClass {
    Class32 = 1,
    Class64 = 2,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
enum ElfData {
    DataLSB = 1,
    DataMSB = 2,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
enum ElfOSAbi {
    OSAbiSysv= 0,
    OSAbiHpux= 1,
    OSAbiNetbsd= 2,
    OSAbiGnu= 3,
    OSAbiSolaris= 6,
    OSAbiAix= 7,
    OSAbiIrix= 8,
    OSAbiFreebsd= 9,
    OSAbiTru64= 10,
    OSAbiModesto= 11,
    OSAbiOpenbsd= 12,
    OSAbiArmAeabi= 64,
    OSAbiArm= 97,
    OSAbiStandalone= 255,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u16)]
enum ElfType {
    None= 0,
    Rel= 1,
    Exec= 2,
    Dyn= 3,
    Core= 4,
    Num= 5,
    Loos= 0xfe00,
    Hios= 0xfeff,
    LoProc= 0xff00,
    HiProc= 0xffff,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u16)]
enum ElfMachine {
    MachineNone = 0,
    MachineM32 = 1,
    MachineSparc = 2,
    Machine386 = 3,
    Machine68k = 4,
    Machine88k = 5,
    MachineIamcu = 6,
    Machine860 = 7,
    MachineMips = 8,
    MachineS370 = 9,
    MachineMipsRs3Le = 10,
    MachineParisc = 15,
    MachineVpp500 = 17,
    MachineSparc32plus = 18,
    Machine960 = 19,
    MachinePpc = 20,
    MachinePpc64 = 21,
    MachineS390 = 22,
    MachineSpu = 23,
    MachineV800 = 36,
    MachineFr20 = 37,
    MachineRh32 = 38,
    MachineRce = 39,
    MachineArm = 40,
    MachineFakeAlpha = 41,
    MachineSh = 42,
    MachineSparcv9 = 43,
    MachineTricore = 44,
    MachineArc = 45,
    MachineH8300 = 46,
    MachineH8300h = 47,
    MachineH8s = 48,
    MachineH8500 = 49,
    MachineIa64 = 50,
    MachineMipsX = 51,
    MachineColdfire = 52,
    Machine68hc12 = 53,
    MachineMma = 54,
    MachinePcp = 55,
    MachineNcpu = 56,
    MachineNdr1 = 57,
    MachineStarcore = 58,
    MachineMe16 = 59,
    MachineSt100 = 60,
    MachineTinyj = 61,
    MachineX8664 = 62,
    MachinePdsp = 63,
    MachinePdp10 = 64,
    MachinePdp11 = 65,
    MachineFx66 = 66,
    MachineSt9plus = 67,
    MachineSt7 = 68,
    Machine68hc16 = 69,
    Machine68hc11 = 70,
    Machine68hc08 = 71,
    Machine68hc05 = 72,
    MachineSvx = 73,
    MachineSt19 = 74,
    MachineVax = 75,
    MachineCris = 76,
    MachineJavelin = 77,
    MachineFirepath = 78,
    MachineZsp = 79,
    MachineMmix = 80,
    MachineHuany = 81,
    MachinePrism = 82,
    MachineAvr = 83,
    MachineFr30 = 84,
    MachineD10v = 85,
    MachineD30v = 86,
    MachineV850 = 87,
    MachineM32r = 88,
    MachineMn10300 = 89,
    MachineMn10200 = 90,
    MachinePj = 91,
    MachineOpenrisc = 92,
    MachineArcCompact = 93,
    MachineXtensa = 94,
    MachineVideocore = 95,
    MachineTmmGpp = 96,
    MachineNs32k = 97,
    MachineTpc = 98,
    MachineSnp1k = 99,
    MachineSt200 = 100,
    MachineIp2k = 101,
    MachineMax = 102,
    MachineCr = 103,
    MachineF2mc16 = 104,
    MachineMsp430 = 105,
    MachineBlackfin = 106,
    MachineSeC33 = 107,
    MachineSep = 108,
    MachineArca = 109,
    MachineUnicore = 110,
    MachineExcess = 111,
    MachineDxp = 112,
    MachineAlteraNios2 = 113,
    MachineCrx = 114,
    MachineXgate = 115,
    MachineC166 = 116,
    MachineM16c = 117,
    MachineDspic30f = 118,
    MachineCe = 119,
    MachineM32c = 120,
    MachineTsk3000 = 131,
    MachineRs08 = 132,
    MachineSharc = 133,
    MachineEcog2 = 134,
    MachineScore7 = 135,
    MachineDsp24 = 136,
    MachineVideocore3 = 137,
    MachineLatticemico32 = 138,
    MachineSeC17 = 139,
    MachineTiC6000 = 140,
    MachineTiC2000 = 141,
    MachineTiC5500 = 142,
    MachineTiArp32 = 143,
    MachineTiPru = 144,
    MachineMmdspPlus = 160,
    MachineCypressM8c = 161,
    MachineR32c = 162,
    MachineTrimedia = 163,
    MachineQdsp6 = 164,
    Machine8051 = 165,
    MachineStxp7x = 166,
    MachineNds32 = 167,
    MachineEcog1x = 168,
    MachineMaxq30 = 169,
    MachineXimo16 = 170,
    MachineManik = 171,
    MachineCraynv2 = 172,
    MachineRx = 173,
    MachineMetag = 174,
    MachineMcstElbrus = 175,
    MachineEcog16 = 176,
    MachineCr16 = 177,
    MachineEtpu = 178,
    MachineSle9x = 179,
    MachineL10m = 180,
    MachineK10m = 181,
    MachineAarch64 = 183,
    MachineAvr32 = 185,
    MachineStm8 = 186,
    MachineTile64 = 187,
    MachineTilepro = 188,
    MachineMicroblaze = 189,
    MachineCuda = 190,
    MachineTilegx = 191,
    MachineCloudshield = 192,
    MachineCorea1st = 193,
    MachineCorea2nd = 194,
    MachineArcCompact2 = 195,
    MachineOpen8 = 196,
    MachineRl78 = 197,
    MachineVideocore5 = 198,
    Machine78kor = 199,
    Machine56800ex = 200,
    MachineBa1 = 201,
    MachineBa2 = 202,
    MachineXcore = 203,
    MachineMchpPic = 204,
    MachineKm32 = 210,
    MachineKmx32 = 211,
    MachineEmx16 = 212,
    MachineEmx8 = 213,
    MachineKvarc = 214,
    MachineCdp = 215,
    MachineCoge = 216,
    MachineCool = 217,
    MachineNorc = 218,
    MachineCsrKalimba = 219,
    MachineZ80 = 220,
    MachineVisium = 221,
    MachineFt32 = 222,
    MachineMoxie = 223,
    MachineAmdgpu = 224,
    MachineRiscv = 243,
    MachineBpf = 247,
    MachineNum = 248,
    MachineAlpha = 0x9026,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u16)]
enum ElfVersion {
    Current = 1,
}
}

#[derive(Debug,PartialEq)]
pub struct ElfIdent {
    tag:        [u8; 4],
    class:      ElfClass,
    data:       ElfData,
    version:    ElfVersion,
    osabi:      ElfOSAbi,
    padding:    [u8; 7],
}

pub fn le_u8(i:&[u8]) -> nom::IResult<&[u8], u8> {
    if i.len() < 1 {
        Err(nom::Err::Incomplete(nom::Needed::Size(1)))
    } else {
        Ok((&i[1..], i[0]))
    }
}

macro_rules! parse_u8_enum {
    ($funcname:ident, $enum:ident) => (
        fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            match le_u8(i) {
                Ok((rest, x)) => {
                    match $enum::from_u8(x) {
                        Some(y) => Ok((rest, y)),
                        None    => Err(nom::Err::Error(error_position!(i, nom::ErrorKind::NoneOf)))
                    }
                },
                Err(e) => Err(e)
            }
        }
    )
}

macro_rules! parse_u16_enum {
    ($funcname:ident, $enum:ident) => (
        fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            match nom::le_u16(i) {
                Ok((rest, x)) => {
                    match $enum::from_u16(x) {
                        Some(y) => Ok((rest, y)),
                        None    => Err(nom::Err::Error(error_position!(i, nom::ErrorKind::NoneOf)))
                    }
                },
                Err(e) => Err(e)
            }
        }
    )
}

macro_rules! parse_u32_enum {
    ($funcname:ident, $enum:ident) => (
        fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            match nom::le_u32(i) {
                Ok((rest, x)) => {
                    match $enum::from_u32(x) {
                        Some(y) => Ok((rest, y)),
                        None    => Err(nom::Err::Error(error_position!(i, nom::ErrorKind::NoneOf)))
                    }
                },
                Err(e) => Err(e)
            }
        }
    )
}

parse_u8_enum!(parse_elf_class, ElfClass);
parse_u8_enum!(parse_elf_data, ElfData);
parse_u8_enum!(parse_elf_version, ElfVersion);
parse_u16_enum!(parse_elf_osabi, ElfOSAbi);

named!(pub parse_elf_ident<ElfIdent>,
    do_parse!(
            _tag:       tag!("\x7fELF")
        >>  _class:     parse_elf_class
        >>  _data:      parse_elf_data
        >>  _version:   parse_elf_version
        >>  _osabi:     parse_elf_osabi
        >>  _padding:   count_fixed!(u8, le_u8, 7)
        >>  (ElfIdent {
            tag:        [_tag[0], _tag[1], _tag[2], _tag[3]],
            class:      _class,
            data:       _data,
            version:    _version,
            osabi:      _osabi,
            padding:    _padding
        })
    )
);
