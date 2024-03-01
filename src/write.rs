use std::fs::File;
use std::io::{self, BufWriter, ErrorKind, Result, Write};
use crossbeam::channel::Receiver;

pub fn write_loop(outfile: &str, write_rx: Receiver<Vec<u8>>) -> Result<()> {
    let mut writer: Box<dyn Write> = if !outfile.is_empty() {
        Box::new(BufWriter::new(File::create(outfile)?))
    } else {
        Box::new(BufWriter::new(io::stdout())) // If the outfile is empty, write to stdout
    };

    loop {
        // DONE Recieve Vector of bytes from stats thread
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

    Ok(()) // Keep the loop going
}
