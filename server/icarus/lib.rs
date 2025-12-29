use libc::{c_char, c_int};
use openssl::symm::{Cipher, Crypter, Mode};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::ptr;

const BLOCK_SIZE: usize = 4 * 1024 * 1024; // 4 MB

fn aes_block_crypt(block: &[u8], key: &[u8], iv: &[u8], mode: Mode) -> Option<Vec<u8>> {
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, mode, key, Some(iv)).ok()?;
    crypter.pad(true);
    let mut out = vec![0u8; block.len() + cipher.block_size()];
    let len = crypter.update(block, &mut out).ok()?;
    let final_len = crypter.finalize(&mut out[len..]).ok()?;
    out.truncate(len + final_len);
    Some(out)
}

#[no_mangle]
pub extern "C" fn process_file_chunked(input_file: *const c_char, output_file: *const c_char, encrypt: c_int) -> c_int {
    if input_file.is_null() || output_file.is_null() { return 0; }

    let input_path = match unsafe { CStr::from_ptr(input_file).to_str() } {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let output_path = match unsafe { CStr::from_ptr(output_file).to_str() } {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let mut f_in = match File::open(input_path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut f_out = match File::create(output_path) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    let key: [u8; 32] = [
        0x10,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
        0x12,0x23,0x34,0x45,0x56,0x67,0x78,0x89
    ];

    let mut buffer = vec![0u8; BLOCK_SIZE];
    let mut iv = [0u8; 16];
    let mut prev_cipher = [0u8; 16];
    let mut first_block = true;

    loop {
        let read_bytes = match f_in.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return 0,
        };
        let block = &buffer[..read_bytes];

        let output_block = if encrypt != 0 {
            // Encryption
            if first_block {
                if openssl::rand::rand_bytes(&mut iv).is_err() { return 0; }
                match aes_block_crypt(block, &key, &iv, Mode::Encrypt) {
                    Some(mut enc_block) => {
                        prev_cipher.copy_from_slice(&enc_block[enc_block.len()-16..]);
                        let mut combined = Vec::with_capacity(16 + enc_block.len());
                        combined.extend_from_slice(&iv);
                        combined.append(&mut enc_block);
                        first_block = false;
                        combined
                    }
                    None => return 0,
                }
            } else {
                match aes_block_crypt(block, &key, &prev_cipher, Mode::Encrypt) {
                    Some(enc_block) => {
                        prev_cipher.copy_from_slice(&enc_block[enc_block.len()-16..]);
                        enc_block
                    }
                    None => return 0,
                }
            }
        } else {
            // Decryption
            let use_iv = if first_block { &block[..16] } else { &prev_cipher };
            let cipher_data = if first_block { &block[16..] } else { block };
            match aes_block_crypt(cipher_data, &key, use_iv, Mode::Decrypt) {
                Some(mut dec_block) => {
                    if !first_block { prev_cipher.copy_from_slice(&block[block.len()-16..]); }
                    first_block = false;
                    dec_block
                }
                None => return 0,
            }
        };

        if f_out.write_all(&output_block).is_err() { return 0; }
    }

    1
}

// ---------------- Free memory ----------------
#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { CString::from_raw(ptr); }
    }
}

#[no_mangle]
pub extern "C" fn free_buffer(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { Vec::from_raw_parts(ptr, 0, 0); }
    }
}

