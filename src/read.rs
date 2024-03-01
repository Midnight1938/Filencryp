use crate::CHUNK_SIZE;
use crossbeam::channel::Sender;
use std::fs::File;
use std::io::{self, BufReader, Read, Result};
use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Nonce, AesGcm};
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;
use rand::{RngCore};

pub fn read_loop(infile: &str, stats_tx: Sender<usize>, write_tx: Sender<Vec<u8>>, decrypt: &str) -> Result<()> {
    let mut reader: Box<dyn Read> = if !infile.is_empty() {
        Box::new(BufReader::new(File::open(infile)?))
    } else {
        Box::new(BufReader::new(io::stdin()))
    };
    let mut buffer = [0; CHUNK_SIZE];

    // Reuse key and nonce bytes
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let mut nonce_bytes = [0; 12];
    let cipher = Aes256Gcm::new(&key);
    OsRng.fill_bytes(&mut nonce_bytes);

    loop {
        let num_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(x) => x,
            Err(_) => break,
        };
        let _ = stats_tx.send(num_read); // Don't care if it can't send stats

        // TODO Decryption
        if write_tx.send(Vec::from(scrambler(decrypt, num_read, &buffer, &cipher, &nonce_bytes))).is_err() {
            break;
        }
    }
    let _ = stats_tx.send(0);
    let _ = write_tx.send(Vec::new()); // empty vec

    Ok(())
}

pub fn scrambler(decrypt: &str, num_read: usize, buffer: &[u8], cipher: &AesGcm<Aes256, U12>, nonce_bytes: &[u8; 12]) -> Vec<u8> {
    if !decrypt.is_empty() {
        let nonce = Nonce::from_slice(&decrypt.as_bytes());
        cipher.decrypt(nonce, &buffer[..num_read]).unwrap().to_vec()
    } else {
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, &buffer[..num_read]).unwrap();

        // Include the nonce in the encrypted data
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        result
    }
}