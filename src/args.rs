use clap::{Arg, Command};
use std::env;

pub struct Args {
    pub infile: String,
    pub outfile: String,
    pub silent: bool,
    pub decrypt: String,
}

impl Args {
    pub fn parse() -> Self {
        let matches = Command::new(" filencryp")
            .arg(Arg::new("infile").help("Read from a file instead of stdin"))
            .arg(
                Arg::new("outfile")
                    .short('o')
                    .long("outfile")
                    // .takes_value(true)
                    .help("Write output to file instead of stdout"),
            )
            .arg(
                Arg::new("silent")
                    .short('s')
                    .long("silent")
                    .help("Silence the output"),
            )
            .arg(
                Arg::new("decrypt")
                    .short('d')
                    .long("decrypt")
                    .help("Indicate Decryption")
            )
            .get_matches(); // Get the matches from the command line

        let infile = matches
            .get_many::<String>("infile")
            .unwrap_or_default()
            .map(|s| s.to_string())
            .collect(); //? Make it a String instead of Option<ValuesFer<'_, String>>
        let outfile = matches
            .get_many::<String>("outfile")
            .unwrap_or_default()
            .map(|s| s.to_string())
            .collect();

        let silent = if matches.contains_id("silent") {
            true
        } else {
            !env::var("PV_SILENT").unwrap_or_default().is_empty()
        }; // Get the silent value from the matches
           // dbg!(infile, outfile, silent);
        let decrypt= matches
            .get_many::<String>("decrypt")
            .unwrap_or_default()
            .map(|s| s.to_string())
            .collect();
        Self {
            infile,
            outfile,
            silent,
            decrypt,
        }
    }
}
