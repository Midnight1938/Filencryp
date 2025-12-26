# PV Crypt - A system level file encryption solution using aes_gcm

## About

A file encryption and decryption software used to encrypt a file using `aes_gcm` library.
Added feature of using pipe to encrypt and decrypt files in a single command.

## Features

- Uses `aes_gcm` library to encrypt and decrypt files
- Able to stream the file for encryption and decryption
- Able to receive and output pipe data

## Usage

### Encryption

```sh
pvcrypt <input file> -o <output file>
```

Or using pipes

```sh
tar -cf - /path/to/your/folder | pvcrypt -o <output file>
```

### Decryption

```sh
pvcrypt <input file> -o <output file> -d <key>
```

## Security notice

- The underlying `aes-gcm-stream` crate does not zeroize its internal key state; key material may remain in process memory until the encryptor/decryptor is dropped. We zeroize our stack copies of key/nonce, but the stream internals are not wiped by the crate. For stronger guarantees, patch the dependency to add zeroize-on-drop or use a stream AEAD that supports zeroization.

- This tool generates a random key and writes it (with the nonce) to a key file (`<output file>.key`, or `key.enc` when writing to stdout). Anyone who can read both the ciphertext and the key file can obviously decrypt the data. Keep the key file private and stored separately from the ciphertext if confidentiality matters.

