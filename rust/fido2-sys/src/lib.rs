//! Raw FFI bindings to libfido2, generated at build time from the system
//! headers so prototypes can never drift from the installed library.
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
