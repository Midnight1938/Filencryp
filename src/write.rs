use std::io::{BufWriter, Write, Result};
use crossbeam::channel::Receiver;

pub fn write_loop(outfile: &str, write_rx: Receiver<Vec<u8>>) -> Result<()> {
    let mut writer: Box<dyn Write> = if !outfile.is_empty() {
        Box::new(BufWriter::new(std::fs::File::open(outfile)?))
    } else {
        Box::new(BufWriter::new(std::io::stdout()))
    };

    loop {
        match write_rx.recv() {
            Ok(buffer) => {
                if buffer.is_empty() {
                    break;
                }
                if let Err(e) = writer.write_all(&buffer) {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        return Ok(());
                    }
                    return Err(e);
                }
            },
            Err(_) => break,
        }
    }

    Ok(())
}