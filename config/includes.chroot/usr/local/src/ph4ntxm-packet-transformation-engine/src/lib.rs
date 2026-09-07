#![deny(unsafe_op_in_unsafe_fn)]

mod crypto;
mod engine;
mod packet;

use std::ptr;
use std::slice;
use std::time::Instant;

use engine::{Engine, Mode};

const PACKET_TRANSFORMATION_ENGINE_ACCEPT: i32 = 1;
const PACKET_TRANSFORMATION_ENGINE_DROP: i32 = 0;
const PACKET_TRANSFORMATION_ENGINE_FATAL: i32 = -1;

fn write_error(target: *mut u8, capacity: usize, message: &str) {
    if target.is_null() || capacity == 0 {
        return;
    }
    let length = message.len().min(capacity - 1);
    unsafe {
        ptr::copy_nonoverlapping(message.as_ptr(), target, length);
        *target.add(length) = 0;
    }
}

#[no_mangle]
/// # Safety
/// `seed` must identify a readable `seed_length` byte region for the duration of the call.
pub unsafe extern "C" fn ph4ntxm_packet_transformation_engine_new(
    mode: u8,
    seed: *const u8,
    seed_length: usize,
) -> *mut Engine {
    if seed.is_null() || seed_length != 32 || mode > 1 {
        return ptr::null_mut();
    }
    let mut key = [0u8; 32];
    unsafe {
        key.copy_from_slice(slice::from_raw_parts(seed, seed_length));
    }
    let mode = if mode == 0 {
        Mode::Linux
    } else {
        Mode::Windows
    };
    Box::into_raw(Box::new(Engine::new(mode, key)))
}

#[no_mangle]
/// # Safety
/// `engine` must be null or a live pointer returned by `ph4ntxm_packet_transformation_engine_new` and not previously freed.
pub unsafe extern "C" fn ph4ntxm_packet_transformation_engine_free(engine: *mut Engine) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine));
        }
    }
}

#[no_mangle]
/// # Safety
/// All non-null buffers must be valid for their declared lengths and must not overlap. `engine` must be exclusively owned by the calling thread for the duration of the call.
pub unsafe extern "C" fn ph4ntxm_packet_transformation_engine_process(
    engine: *mut Engine,
    input: *const u8,
    input_length: usize,
    outbound: u8,
    interface: u32,
    checksum_not_ready: u8,
    output: *mut u8,
    output_capacity: usize,
    output_length: *mut usize,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if engine.is_null()
        || input.is_null()
        || output.is_null()
        || output_length.is_null()
        || input_length == 0
        || input_length > u16::MAX as usize
        || outbound > 1
        || checksum_not_ready > 1
    {
        write_error(error, error_capacity, "invalid native-core call");
        return PACKET_TRANSFORMATION_ENGINE_FATAL;
    }
    let packet = unsafe { slice::from_raw_parts(input, input_length) };
    let result =
        unsafe { &mut *engine }.process(packet, outbound == 1, interface, checksum_not_ready == 1);
    match result {
        Ok(transformed) => {
            if transformed.len() > output_capacity {
                write_error(
                    error,
                    error_capacity,
                    "native-core output capacity exceeded",
                );
                return PACKET_TRANSFORMATION_ENGINE_FATAL;
            }
            unsafe {
                ptr::copy_nonoverlapping(transformed.as_ptr(), output, transformed.len());
                *output_length = transformed.len();
            }
            PACKET_TRANSFORMATION_ENGINE_ACCEPT
        }
        Err(message) => {
            write_error(error, error_capacity, message);
            unsafe {
                *output_length = 0;
            }
            PACKET_TRANSFORMATION_ENGINE_DROP
        }
    }
}

#[no_mangle]
/// # Safety
/// `engine` must be a live pointer returned by `ph4ntxm_packet_transformation_engine_new` and exclusively owned for the duration of the call.
pub unsafe extern "C" fn ph4ntxm_packet_transformation_engine_maintenance(engine: *mut Engine) -> i32 {
    if engine.is_null() {
        return PACKET_TRANSFORMATION_ENGINE_FATAL;
    }
    unsafe { &mut *engine }.remove_stale(Instant::now());
    0
}

#[no_mangle]
pub extern "C" fn ph4ntxm_packet_transformation_engine_self_test() -> i32 {
    let digest = crypto::blake2s(b"", b"abc", 32);
    let expected = [
        0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45,
        0x2f, 0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67,
        0x59, 0x82,
    ];
    if digest != expected
        || packet::checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]) != 0x220d
    {
        PACKET_TRANSFORMATION_ENGINE_FATAL
    } else {
        0
    }
}
