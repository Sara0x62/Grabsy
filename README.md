# Grabsy
Grabsy is a Google Chrome password grabber
I might add more options later but it's a learning project so far



### How it works
The main chromium browsers,
seem to all store passwords the same way
The only difference being the path to the location.
They are also all stored in a local sqlite database

1st we set the base path for the requested browser
then we get an "Encrypted Key" from the "Local State" file;
We will also have to decrypt the key on windows using the
    -> CryptUnprotectData() function
This is a large JSON file containing some configs etc.

Then we try to make a database connection
to the local database file.
After that connection is established,
send a query for all the following values:
    "action_url, username_value, password_value"

At this point all thats left is decrypting the password
It uses AES256-GCM with the
    master key being our encrypted key from earlier
        (Now decrypted)
    and a 12 byte random IV
    and prepends it's signature "v10" infront
example; "v10[..iv..][encrypted password]"
