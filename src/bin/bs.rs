extern crate bs;
extern crate structopt;
extern crate sodiumoxide;

use bs::{sign, verify};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "BetterSign", 
    version = "0.1",
    author = "David Huseby <dhuseby@linuxfoundation.org>",
    about = "BetterSign signing tool",
)]
struct Opt {
    /// verbose output
    #[structopt(long = "verbose", short = "v")]
    verbose: bool,

    /// the file descriptor number to use for machine parseable status
    #[structopt(long = "status-fd")]
    fd: Option<u32>,

    /// the subcommand operation
    #[structopt(subcommand)]
    cmd: Command
}

#[derive(Debug, StructOpt)]
enum Command {

    #[structopt(name = "sign")]
    /// Sign the given file(s) or data.
    Sign {
        /// DIDDir root path or default if unspecified.
        #[structopt(long = "diddir")]
        dir: Option<String>,

        /// DID for the identity to use for signing.
        #[structopt(long = "id")]
        id: Option<String>,

        /// The format of the signature output, either "lds" or "jwt"
        #[structopt(long = "format")]
        fmt: Option<String>,

        /// The file to save the signature in or stdout if unspecified.
        #[structopt(short = "o", parse(from_os_str))]
        output: Option<PathBuf>,

        /// List of files to sign or '-' if signing data passed through stdin.
        #[structopt(name = "FILES", parse(from_os_str))]
        files: Vec<PathBuf>,
    },
   
    #[structopt(name = "verify")]
    /// Verify the given signature
    Verify {
        /// the manifest file to verify
        #[structopt(name = "MANIFEST", parse(from_os_str))]
        manifest: PathBuf
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    // initialize sodiumoxide
    sodiumoxide::init().unwrap();

    // parse the command line flags
    let opt = Opt::from_args();
    match opt.cmd {
        Command::Sign { dir, id, fmt, output, files } => {
            let signature = sign::sign(opt.verbose, &opt.fd, &dir, &id, files)?;

            // output the signature to a file or stdout
            let mut out_writer = match output {
                Some(p) => {
                    let path = Path::new(&p);
                    Box::new(File::create(&path).unwrap()) as Box<Write>
                }
                None => Box::new(io::stdout()) as Box<Write>,
            };
            out_writer.write(signature.as_bytes())?;
        },
        Command::Verify { manifest } => {
            verify::verify(opt.verbose, &opt.fd, &manifest)?;
        },
    }

    Ok(())
}
