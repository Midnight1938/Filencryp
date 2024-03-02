use crate::CHUNK_SIZE;
use crossbeam::channel::Sender;

use std::fs;
use std::fs::File;
use std::io::{self, BufReader, Read, Result, Write};
use std::path::Path;

use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, generic_array::GenericArray, OsRng};

pub fn read_loop(infile: &str, stats_tx: Sender<usize>, write_tx: Sender<Vec<u8>>, deccode: &str) -> Result<()> {
    let mut reader: Box<dyn Read> = if !infile.is_empty() {
        Box::new(BufReader::new(File::open(infile)?))
    } else {
        Box::new(BufReader::new(io::stdin()))
    };
    let mut buffer = [0; CHUNK_SIZE];
    let keydata = if Path::new(deccode).exists() {
        read_key(deccode)
    } else {
        eprintln!("Key file not found. Generating a new key.");
        //? Generate a new key and save it to the file
        let key = Aes256Gcm::generate_key(&mut OsRng).as_slice().to_vec();
        key_to_file(infile, &key).expect("Error saving key to file");
        Ok(key)
    };
    let keydat = match keydata {
        Ok(key) => key,
        Err(err) => {
            eprintln!("Error reading/generating key: {}", err);
            return Ok(());
        }
    };

    loop {
        let num_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(x) => x,
            Err(_) => break,
        };
        let _ = stats_tx.send(num_read); // Dont care if it cant see stats

        let output = if !fs::metadata(deccode).is_ok() {
            let key = GenericArray::from_slice(&keydat);
            let cipher = Aes256Gcm::new(key);
            let nonce = GenericArray::from_slice(&[0u8; 12]);

            cipher.encrypt(nonce, &buffer[..num_read])
                .expect("Encryption failed")
        } else {
            let key = GenericArray::from_slice(&keydat);
            let cipher = Aes256Gcm::new(key);
            let nonce = GenericArray::from_slice(&[0u8; 12]);

            cipher.decrypt(nonce, &buffer[..num_read])
                .expect("Decryption failed!")
        };

        if write_tx.send(Vec::from(output)).is_err() {
            break;
        };
    }
    let _ = stats_tx.send(0);
    let _ = write_tx.send(Vec::new()); // empty vec

    Ok(())
}

fn read_key(decode: &str) -> Result<Vec<u8>> {
    let mut file = File::open(decode)?;
    let mut key = Vec::new();
    file.read_to_end(&mut key)?;
    Ok(key)
}

fn key_to_file(infile: &str, key: &[u8]) -> io::Result<()> {
    let mut key_file = File::create(format!("{}.key", infile)).unwrap();
    key_file.write_all(&key).unwrap();
    Ok(())
}