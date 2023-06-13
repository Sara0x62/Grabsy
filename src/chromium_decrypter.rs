use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use rusqlite::Connection;

use anyhow::Result;

use crate::chromium::ChromiumBrowser;

pub struct Decrypter {
    master_key: Vec<u8>,
    db_file: String,
    browser: ChromiumBrowser
}

#[derive(Debug)]
struct Login {
    url: String,
    user: String,
    password: Vec<u8>,
}


impl Decrypter {
    pub fn new(master_key: Vec<u8>, db_file: String, browser: ChromiumBrowser)  -> Decrypter {
        Decrypter {
            master_key: master_key,
            db_file: db_file,
            browser: browser,
        }
    }

    /// Run decryptor, 
    /// if print is true -> print output
    /// Otherwise write to file
    pub fn run(&self, _print: bool) -> Result<()> {
        let db_conn = Connection::open(&self.db_file)?;

        let query = "SELECT action_url, username_value, password_value FROM logins";       
        let mut stmt = db_conn.prepare(query)?;

        let login_iter = stmt.query_map([],
            |row| {
                Ok(Login {
                    url: row.get(0)?,
                    user: row.get(1)?,
                    password: row.get(2)?,
                })
            }
        )?;

        // Printing output - 
        // TODO: Add saving to file perhaps
        println!(" {:^19} |  Username  | Password", "URL");
        let mut count = 0;
        for value in login_iter.flatten() {
            if let Ok(password) = self.decrypt_password(&value.password) {
                // If successful decrypting the password, print

                if !value.url.is_empty() 
                && !value.user.is_empty() 
                && !value.password.is_empty()
                {
                    println!("{}  |  {}  |  {}", value.url, value.user, password);
                }

                count += 1;
            }
        }

        println!("Found {} accounts for {}", count, self.browser);

        Ok(())
    }

    pub fn decrypt_password(&self, password: &Vec<u8>) -> Result<String, aes_gcm::Error> {

        // Get the "Initialization Vector" - 12 bytes
        // skipping the first bytes as we dont need the "v10" tag
        let iv = &password[3..15];

        // The rest is the password
        let passw = &password[15..];

        // Convert our key to a "Key" object
        let mut key: [u8; 32] = [0; 32];
        key.copy_from_slice(&self.master_key[..]);
        let key: &Key<Aes256Gcm> = &key.into();

        // Setup our cipher
        let cipher = Aes256Gcm::new(&key);
        // Setup our "Nonce" or IV
        let nonce = Nonce::from_slice(iv);

        // Decript to plaintext
        let plaintext = cipher.decrypt(&nonce, passw)?;

        // Convert to string
        let out = String::from_utf8(plaintext).unwrap();

        Ok(out)
    }
}