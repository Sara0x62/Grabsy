# Grabsy
Grabsy is a Chromium password grabber
I might add more options later but it's a learning project so far



## How it works
The main chromium browsers, seem to all store passwords the same way

The only difference being the path to the location. 
They are also all stored in a local sqlite database

### 1st, Get the master key
1st we set the base path for the requested browser
then we get an "Encrypted Key" from the "Local State" file;
We will also have to decrypt the key on windows using the
    -> `CryptUnprotectData()` function
the key is inside a large json file, nested under
```json
"os_crypt": {
        "encrypted_key": "...master key is here..."
```


### Open up the local database
Here we try to make a database connection
to the local database file.
After that connection is established we send a query for all the following values:

`"SELECT action_url, username_value, password_value FROM logins"`


### Decrypt the passwords
At this point all thats left is decrypting the password
Thes are encrypted with AES256-GCM - to decrypt we need a
 - master key (this is the key we decrypted)
 - An Initialization Vector - in this case 12 
 - Ignore the "v10" prefix
 - The rest is the password

example; 
`"v10[..iv..][encrypted password]"`
