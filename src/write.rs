use crossbeam::channel::Receiver;
use std::fs::File;
use std::io::{self, BufWriter, ErrorKind, Result, Write};

use aes_gcm_stream::Aes256GcmStreamEncryptor;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

pub fn write_loop(outfile: &str, write_rx: Receiver<Vec<u8>>, deccode: &str) -> Result<()> {
    let mut writer: Box<dyn Write> = if !outfile.is_empty() {
        Box::new(BufWriter::new(File::create(outfile)?))
    } else {
        Box::new(BufWriter::new(io::stdout())) // If the outfile is empty, write to stdout
    };

    if !deccode.is_empty() {
        loop {
            let buffer = write_rx.recv().unwrap();
            if buffer.is_empty() {
                break;
            };
            if let Err(e) = writer.write_all(&buffer) {
                if e.kind() == ErrorKind::BrokenPipe {
                    return Ok(()); // stop cleanly
                }
                return Err(e);
            };
        }
    } else {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);
        
        write_nonce_and_key(&nonce, &key)?;
        let mut encryptor = Aes256GcmStreamEncryptor::new(key, &nonce);
        loop {
            // DONE Recieve Vector of bytes from stats thread
            let buffer = write_rx.recv().unwrap();
            if buffer.is_empty() {
                break;
            };

            let buffer = if write_rx.is_empty() {
                let (last_block, tag) = encryptor.finalize();
                let mut final_buffer = buffer;
                final_buffer.extend_from_slice(&last_block);
                final_buffer.extend_from_slice(&tag);
                final_buffer
            } else {
                encryptor.update(&buffer)
            };

            if let Err(e) = writer.write_all(&buffer) {
                if e.kind() == ErrorKind::BrokenPipe {
                    return Ok(()); // stop cleanly
                }
                return Err(e);
            };
            nonce.zeroize();
            key.zeroize();
        }
    }

    Ok(()) // Keep the loop going
}
fn write_nonce_and_key(nonce: &[u8; 32], key: &[u8; 32]) -> Result<()> {
    let mut file = File::create("key.enc")?;
    file.write_all(nonce)?;
    file.write_all(key)?;
    Ok(())
}
