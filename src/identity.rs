use base64::{decode_config, URL_SAFE};
use crate::{Error, Result};
use diddir::DIDDir;
use regex::Regex;
use serde_json::{self, Value as JsonValue};
use sodiumoxide::crypto::secretbox::{
    self, 
    Key as BoxKey,
    KEYBYTES,
    Nonce as BoxNonce,
    NONCEBYTES
};
use sodiumoxide::crypto::sign::{
    PublicKey,
    SecretKey,
    PUBLICKEYBYTES,
    SECRETKEYBYTES
};
use sodiumoxide::crypto::pwhash::argon2id13::{
    self,
    Salt as PwSalt,
    SALTBYTES,
    OPSLIMIT_SENSITIVE,
    MEMLIMIT_SENSITIVE
};
use std::convert::{self, TryFrom};

#[derive(Clone)]
pub struct VerifyKey(pub [u8; PUBLICKEYBYTES]);

impl convert::TryFrom<&String> for VerifyKey {
    type Error = Error;

    fn try_from(sb: &String) -> Result<Self> {
        static PUBLICKEY_REGEX: &'static str = 
            r"@(?P<data>[A-Za-z0-9-_=]+).ed25519\n*";

        // 1. use regex to extract base64 encoded verify key
        let re = Regex::new(PUBLICKEY_REGEX)?;
        if !re.is_match(sb) {
            return Err(Error::InvalidEncoding("not valid sb public key".to_string()));
        }
        let caps = re.captures(sb)?;
        let cap = caps.name("data")?;

        // 2. decode the base64 into a Vec<u8>
        let data = decode_config(cap.as_str(), URL_SAFE)?;
        
        //println!("\nVerifyKey: {:x}", ByteBuff(&data));

        // 3. create a verify key from the binary
        if data.as_slice().len() != PUBLICKEYBYTES {
            return Err(Error::Syntax("not the right number of bytes for a verify key".to_string()));
        }

        let mut vk = VerifyKey([0; PUBLICKEYBYTES]);
        {
            let VerifyKey(ref mut vkb) = vk;
            vkb.copy_from_slice(&data.as_slice());
        }
        Ok(vk)
    }
}

impl convert::Into<PublicKey> for VerifyKey {
    fn into(self) -> PublicKey {
        let mut pk = PublicKey([0; PUBLICKEYBYTES]);
        {
            let PublicKey(ref mut pkb) = pk;
            pkb.copy_from_slice(&self.0);
        }
        pk
    }
}

#[derive(Clone)]
pub struct SignKey(pub [u8; SECRETKEYBYTES]);

impl convert::TryFrom<&JsonValue> for SignKey
{
    type Error = Error;

    fn try_from(json: &JsonValue) -> Result<Self> {
        // 1. get the SB encoded secret box from the JSON object
        let sb_box = String::from(json["secrets"]["signing_key"].as_str().unwrap());

        // 2. use regex to extract the base64 encoded secret box
        static SECRETKEY_REGEX: &'static str = 
            r"(?P<data>[A-Za-z0-9-_=]+).box.xsalsa20poly1305\n*";
        let re = Regex::new(SECRETKEY_REGEX)?;
        if !re.is_match(&sb_box) {
            return Err(Error::InvalidEncoding("not valid sb secret box".to_string()));
        }
        let caps = re.captures(&sb_box)?;
        let data = caps.name("data")?;

        // 3. decode the base64 into a Vec<u8>
        let box_data = decode_config(data.as_str(), URL_SAFE)?;

        // 4. create a Nonce from the nonce bytes in the secret box
        let mut nonce = BoxNonce([0; NONCEBYTES]);
        {
            let BoxNonce(ref mut nb) = nonce;
            nb.copy_from_slice(&box_data[..NONCEBYTES]);
        }

        // 5. create a Salt from the nonce bytes in the secret box
        let mut salt = PwSalt([0; SALTBYTES]);
        {
            let PwSalt(ref mut sb) = salt;
            sb.copy_from_slice(&nonce[(NONCEBYTES - SALTBYTES)..]);
        }

        // 6. get the password from the user
        let passwd = b"test";

        // 7. derive the secret box key from the password and salt
        let mut box_key = BoxKey([0; KEYBYTES]);
        {
            let BoxKey(ref mut kb) = box_key;
            argon2id13::derive_key(kb, passwd, &salt,
                               OPSLIMIT_SENSITIVE,
                               MEMLIMIT_SENSITIVE)?;
        }

        // 4. decrypt the secret box and create a SignKey from the plaintext
        let mut bb = Vec::new();
        bb.extend_from_slice(&box_data[NONCEBYTES..]);
        let sign_key_data = match secretbox::open(&bb.as_slice(), &nonce, &box_key) {
            Ok(m) => m,
            Err(()) => {
                return Err(Error::Syntax("decryption failed".to_string()));
            }
        };
        /*
        {
            println!("\nPassword: test");

            let PwSalt(ref sb) = salt;
            println!("\nSalt: {:x}", ByteBuff(sb));

            let BoxKey(ref kb) = box_key;
            println!("\nBoxKey: {:x}", ByteBuff(kb));

            println!("\nSignKey: {:x}", ByteBuff(&sign_key_data));

            let BoxNonce(ref nb) = nonce;
            println!("\nNonce: {:x}", ByteBuff(nb));

            println!("\nSecretBox: {:x}", ByteBuff(&box_data.as_slice()));
        }
        */

        if sign_key_data.as_slice().len() != SECRETKEYBYTES {
            return Err(Error::Syntax("not the right number of bytes for a SignKey".to_string()));
        }

        let mut sk = SignKey([0; SECRETKEYBYTES]);
        {
            let SignKey(ref mut skb) = sk;
            skb.copy_from_slice(&sign_key_data.as_slice());
        }
        Ok(sk)
    }
}

impl convert::Into<SecretKey> for SignKey {
    fn into(self) -> SecretKey {
        let mut sk = SecretKey([0; SECRETKEYBYTES]);
        {
            let SecretKey(ref mut skb) = sk;
            skb.copy_from_slice(&self.0);
        }
        sk
    }
}

pub trait Identity {
    fn pkid(&self) -> String;
    fn verify_key(&self) -> Option<VerifyKey>;
    fn sign_key(&self) -> Option<SignKey>;
}

struct PublicIdentity {
    pkid: String,
    verify_key: VerifyKey,
}

struct PrivateIdentity {
    pkid: String,
    verify_key: VerifyKey,
    sign_key: SignKey,
}

/*
struct ByteBuff<'a>(&'a [u8]);

impl<'a> std::fmt::LowerHex for ByteBuff<'a> {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        for byte in self.0 {
            fmtr.write_fmt(format_args!("{:02x}", byte)).unwrap();
        }
        Ok(())
    }
}
*/

impl Identity for PublicIdentity {
    fn pkid(&self) -> String {
        self.pkid.clone()
    }
    fn verify_key(&self) -> Option<VerifyKey> {
        Some(self.verify_key.clone())
    }
    fn sign_key(&self) -> Option<SignKey> {
        None
    }
}

impl convert::TryFrom<(&String, &JsonValue)> for PublicIdentity {
    type Error = Error;

    fn try_from(val: (&String, &JsonValue)) -> Result<Self> {
        let (pkid, _) = val;

        Ok(PublicIdentity {
            pkid: pkid.to_owned(),
            verify_key: VerifyKey::try_from(pkid)?
        })
    }
}

impl Identity for PrivateIdentity {
    fn pkid(&self) -> String {
        self.pkid.clone()
    }
    fn verify_key(&self) -> Option<VerifyKey> {
        Some(self.verify_key.clone())
    }
    fn sign_key(&self) -> Option<SignKey> {
        Some(self.sign_key.clone())
    }
}

impl convert::TryFrom<(&String, &JsonValue)> for PrivateIdentity {
    type Error = Error;

    fn try_from(val: (&String, &JsonValue)) -> Result<Self> {
        let (pkid, json) = val;

        Ok(PrivateIdentity {
            pkid: pkid.to_owned(),
            verify_key: VerifyKey::try_from(pkid)?,
            sign_key: SignKey::try_from(json)?
        })
    }
}

pub fn from_pkid_or_alias(diddir: &DIDDir, pkid_or_alias: &Option<String>) -> Result<Box<Identity>> {
    // if no pkid or alias given, try using "default"
    let poa = match pkid_or_alias {
        Some(value) => value.to_owned(),
        None => "default".to_owned()
    };

    // dereference the alias if one was passed in
    let pkid = match diddir.get_pkid_from_alias(&poa) {
        Ok(pkid) => pkid,
        _ => poa
    };

    // get the contents of the identity JSON file
    let id_str = diddir.get_identity(&pkid)?;

    // deserialize the JSON
    let json: JsonValue = serde_json::from_str(id_str.as_str())?;

    if !json.is_object() {
        return Err(Error::InvalidEncoding("Identity file contents is not a JSON map".to_string()));
    }

    // check to see if we can make a public or private identity
    if !json["secrets"].is_null() && !json["secrets"]["signing_key"].is_null() {
        Ok(Box::new(PrivateIdentity::try_from((&pkid, &json))?))
    } else {
        Ok(Box::new(PublicIdentity::try_from((&pkid, &json))?))
    }
}
