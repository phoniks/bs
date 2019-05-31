extern crate diddir;

use base64::{encode_config, URL_SAFE};
use indicatif::{ProgressBar, ProgressStyle};
use diddir::{Config, DIDDir};
use crate::Result;
use crate::identity;
use crate::fs;
use sodiumoxide::crypto::sign::{self, PublicKey, SecretKey, Signature };
use std::path::{Path, PathBuf};

fn get_config(diddir: &Option<String>) -> Result<Config> {
    match diddir {
        Some(root) => Ok(Config::with_path(Path::new(root))),
        None => Ok(Config::new())
    }
}

pub fn sign(_verbose: bool,
            _status_fd: &Option<u32>,
            kdroot: &Option<String>, 
            pkid_or_alias: &Option<String>, 
            files: Vec<PathBuf>) -> Result<String> {

    // scan the files recursively and hash them
    let hashes = fs::hash(files);

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner} {wide_msg}"));
    pb.enable_steady_tick(100);
    pb.set_message("Loading DIDDir...");

    let config = get_config(kdroot)?;
    let diddir = DIDDir::open_or_init(&config)?;

    pb.set_message("Unlocking signing key...");
    let identity = identity::from_pkid_or_alias(&diddir, pkid_or_alias)?;

    // construct the JSON to sign
    let mut json = "{\n  \"files\": {\n".to_string();
    for i in 0..hashes.len() {
        let hash = &hashes[i];
        let sb = format!("    \"{}\": \"&{}.sha512_256\"", hash.path.to_str()?,
                         encode_config(&hash.hash, URL_SAFE));
        json.push_str(&sb);
        if i < (hashes.len() - 1) {
            json.push_str(",\n");
        } else {
            json.push_str("\n");
        }
    }
    json.push_str("  }");

    let mut sign_json = json.to_owned();
    sign_json.push_str("\n}");

    pb.set_message("Signing JSON Manifest...");

    // get the JSON signature
    let signature = {
        if let Some(signk) = identity.sign_key() {
            let sk: SecretKey = signk.into();
            let sig = sign::sign_detached(sign_json.as_bytes(), &sk);
            let Signature(ref sb) = sig;
            format!("{}.sig.ed25519", encode_config(&sb.to_vec(), URL_SAFE))
        } else {
            "no sign key".to_string()
        }
    };

    // get the pkid
    let pkid = {
        if let Some(verifyk) = identity.verify_key() {
            let pk: PublicKey = verifyk.into();
            let PublicKey(ref pkb) = pk;
            format!("@{}.ed25519", encode_config(pkb, URL_SAFE))
        } else {
            "no verify key".to_string()
        }
    };

    // create the final JSON
    let mut final_json = json.to_owned();
    final_json.push_str(",\n  \"signatures\": {\n");
    let sig = format!("    \"{}\": \"{}\"", pkid, signature);
    final_json.push_str(&sig);
    final_json.push_str("\n  }\n}");
    
    pb.set_message("Done.");
    
    pb.finish_and_clear();

    Ok(final_json)
}
