#![no_main]

use core::hint::black_box;
use libfuzzer_sys::fuzz_target;
use patient_registry::validation::validate_did_bytes;

// Must never panic: only Ok / Err.
fuzz_target!(|data: &[u8]| {
    let _ = black_box(validate_did_bytes(data));
});
