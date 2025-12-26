# PV Crypt - A system level file encryption solution using aes_gcm

# Known Issue:
aesgcmstream does not zeroize on drop
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
