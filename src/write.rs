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
            let buffer = match write_rx.recv() {
                Ok(buffer) => buffer,
                Err(_) => break,
            };
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
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);

        write_nonce_and_key(outfile, &nonce, &key)?;
        let mut encryptor = Aes256GcmStreamEncryptor::new(key, &nonce);
        loop {
            // DONE Recieve Vector of bytes from stats thread
            let buffer = match write_rx.recv() {
                Ok(buffer) => buffer,
                Err(_) => break,
            };
            if buffer.is_empty() {
                break;
            };

            let ciphertext = encryptor.update(&buffer);

            if !ciphertext.is_empty() {
                if let Err(e) = writer.write_all(&ciphertext) {
                    if e.kind() == ErrorKind::BrokenPipe {
                        nonce.zeroize();
                        key.zeroize();
                        return Ok(()); // stop cleanly
                    }
                    nonce.zeroize();
                    key.zeroize();
                    return Err(e);
                };
            }
        }

        let (last_block, tag) = encryptor.finalize();

        if !last_block.is_empty() {
            if let Err(e) = writer.write_all(&last_block) {
                if e.kind() == ErrorKind::BrokenPipe {
                    nonce.zeroize();
                    key.zeroize();
                    return Ok(()); // stop cleanly
                }
                nonce.zeroize();
                key.zeroize();
                return Err(e);
            };
        }

        if let Err(e) = writer.write_all(&tag) {
            if e.kind() == ErrorKind::BrokenPipe {
                nonce.zeroize();
                key.zeroize();
                return Ok(()); // stop cleanly
            }
            nonce.zeroize();
            key.zeroize();
            return Err(e);
        };

        nonce.zeroize();
        key.zeroize();
    }

    Ok(()) // Keep the loop going
}
fn write_nonce_and_key(outfile: &str, nonce: &[u8; 12], key: &[u8; 32]) -> Result<()> {
    let key_path = if !outfile.is_empty() {
        format!("{}.key", outfile)
    } else {
        "key.enc".to_string()
    };
    let mut file = File::create(key_path)?;
    file.write_all(nonce)?;
    file.write_all(key)?;
    Ok(())
}
