#[macro_export]
macro_rules! parse_u8_enum {
    ($funcname:ident, $enum:ident) => {
        fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            ::nom::combinator::map_opt(::nom::number::complete::le_u8, $enum::from_u8)(i)
        }
    };
    ($visibility:vis $funcname:ident, $enum:ident) => {
        $visibility fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            ::nom::combinator::map_opt(::nom::number::complete::le_u8, $enum::from_u8)(i)
        }
    };
}

#[macro_export]
macro_rules! parse_u16_enum {
    ($funcname:ident, $enum:ident) => {
        fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            ::nom::combinator::map_opt(::nom::number::complete::le_u16, $enum::from_u16)(i)
        }
    };
    ($visibility:vis $funcname:ident, $enum:ident) => {
        $visibility fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            ::nom::combinator::map_opt(::nom::number::complete::le_u16, $enum::from_u16)(i)
        }
    };
}

#[macro_export]
macro_rules! parse_u32_enum {
    ($funcname:ident, $enum:ident) => {
        fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            ::nom::combinator::map_opt(::nom::number::complete::le_u32, $enum::from_u32)(i)
        }
    };
    ($visibility:vis $funcname:ident, $enum:ident) => {
        $visibility fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            ::nom::combinator::map_opt(::nom::number::complete::le_u32, $enum::from_u32)(i)
        }
    };
}

#[macro_export]
macro_rules! parse_u64_enum {
    ($funcname:ident, $enum:ident) => {
        fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            ::nom::combinator::map_opt(::nom::number::complete::le_u64, $enum::from_u64)(i)
        }
    };
    ($visibility:vis $funcname:ident, $enum:ident) => {
        $visibility fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            ::nom::combinator::map_opt(::nom::number::complete::le_u64, $enum::from_u64)(i)
        }
    };
}
