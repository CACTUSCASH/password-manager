# Password Manager

This repository contains a **minimal command-line password manager** built with
Python. It demonstrates core concepts of cryptography and secure data storage
without relying on external libraries, making it easy to understand and hack
on.

## Features

- Protects all credentials behind a single master password
- Stores service names, usernames, and passwords in an encrypted JSON file
- Derives a cryptographic key from your master password using SHA-256
- Uses XOR encryption to obscure your data (suitable for demonstration,
  *not for production*)
- Includes integrity checking via SHA-256 to detect file tampering
- Simple interactive menu to add, list, and retrieve credentials

## Running the Program

Run the script from your terminal:

```bash
python password_manager.py
```

The first time you run it, it will create a new `passwords.json` file in the
current directory. You'll be prompted for a master password, then you can add
new entries or retrieve existing ones. Make sure to remember your master
password—if you forget it, you won't be able to decrypt your stored
credentials.

## Disclaimer

This project is for educational purposes. XOR encryption is **not** secure for
real-world use. To build a production-ready password manager, consider using
established libraries like [`cryptography`](https://cryptography.io/) and
audited data formats such as encrypted SQLite databases.

## Learning objectives

This project showcases:

- Key derivation and symmetric encryption concepts
- Secure input handling with `getpass`
- Data integrity verification using checksums
- JSON serialization for structured storage

It's a strong addition to a cybersecurity portfolio, demonstrating an
understanding of how password managers work under the hood.
