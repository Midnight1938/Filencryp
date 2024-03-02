use crate::CHUNK_SIZE;
use aes_gcm::{
    aead::{Aead, Key, OsRng},
    Aes256Gcm, KeyInit, Nonce,
};
use crossbeam::channel::Sender;
use rand::RngCore;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Result, Write};

pub fn read_loop(
    infile: &str, stats_tx: Sender<usize>, write_tx: Sender<Vec<u8>>, key_file: &str) -> Result<()> {
    let mut reader: Box<dyn Read> = if !infile.is_empty() {
        Box::new(BufReader::new(File::open(infile)?))
    } else {
        Box::new(BufReader::new(io::stdin()))
    };
    let mut buffer = [0; CHUNK_SIZE];

    // Reuse key and nonce bytes
    let mut nonce_bytes = [0; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let key = load_or_generate_key(key_file, infile);
    let cipher = Aes256Gcm::new(&key);
            let nonce = Nonce::from_slice(&nonce_bytes);

    loop {
        let num_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(x) => x,
            Err(_) => break,
        };
        let _ = stats_tx.send(num_read); // Don't care if it can't send stats

        // TODO Decryption
        let result = if fs::metadata(key_file).is_ok() {
            cipher.decrypt(nonce, &buffer[..num_read]).unwrap().to_vec()
        } else {
            let ciphertext = cipher.encrypt(nonce, &buffer[..num_read]).unwrap();

            // Include the nonce in the encrypted data
            let mut result = nonce_bytes.to_vec();
            result.extend_from_slice(&ciphertext);
            result
        };

        if write_tx.send(result).is_err() {
            break;
        }
    }
    let _ = stats_tx.send(0);
    let _ = write_tx.send(Vec::new()); // empty vec

    Ok(())
}

// TODO Pull in a file properly
fn load_or_generate_key(key_file: &str, infile: &str) -> Key<Aes256Gcm> {
    if fs::metadata(key_file).is_ok() {
        // Key file exists, load the key
        let mut key_file = BufReader::new(File::open(key_file).unwrap());
        let mut key = Vec::new();
        key_file.read_to_end(&mut key).unwrap();
        *Key::<Aes256Gcm>::from_slice(key.as_slice())
    } else {
        // Key file doesn't exist, generate a new key and save it
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let mut key_file = File::create(format!("{}.key", infile.replace("\"", ""))).unwrap();

        key_file.write_all(&key).unwrap();
        key
    }
}
