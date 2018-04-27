#[macro_use]
extern crate enum_primitive;

#[macro_use]
extern crate nom;


#[allow(dead_code)]
#[allow(unused_macros)]

pub mod header;
pub use header::*;

pub mod elf64;
pub use elf64::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
