"""Simple Password Manager
==========================

This command‑line password manager allows you to securely store and retrieve
passwords for different services using a single master password. The
implementation uses basic XOR encryption with a key derived from the master
password. While this approach is not suitable for production use, it
demonstrates the concepts of key derivation, symmetric encryption, and secure
storage in a way that is easy to understand and extend.

Features:
 * Create or unlock a password store by entering a master password
 * Add new service credentials (service name, username, password)
 * List stored services
 * Retrieve credentials for a specific service

Stored credentials are saved to a JSON file (default: `passwords.json`) in
the working directory. The file contains the encrypted data along with a
checksum to detect tampering.

This project showcases basic cryptography concepts relevant to
cybersecurity and can serve as a starting point for more advanced
implementations using robust libraries like `cryptography`.
"""

import base64
import getpass
import hashlib
import json
import os
import sys
from typing import Dict, Tuple


STORE_FILE = "passwords.json"


def derive_key(master_password: str) -> bytes:
    """Derive a 32‑byte key from the master password using SHA‑256.

    Args:
        master_password: The master password entered by the user.

    Returns:
        A 32‑byte key derived from the password.
    """
    return hashlib.sha256(master_password.encode()).digest()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Encrypt/decrypt data using XOR with a repeating key.

    Args:
        data: Data to encrypt or decrypt.
        key: Key to XOR with.

    Returns:
        The result of XOR'ing the data with the key.
    """
    expanded_key = (key * (len(data) // len(key) + 1))[: len(data)]
    return bytes(a ^ b for a, b in zip(data, expanded_key))


def encrypt_entry(entry: Dict[str, str], key: bytes) -> Dict[str, str]:
    """Encrypt a single credential entry.

    Args:
        entry: A dictionary with keys 'service', 'username', 'password'.
        key: Key used for encryption.

    Returns:
        A dictionary with base64‑encoded encrypted values.
    """
    encrypted = {}
    for field, value in entry.items():
        data = value.encode()
        cipher = xor_bytes(data, key)
        encrypted[field] = base64.b64encode(cipher).decode()
    return encrypted


def decrypt_entry(entry: Dict[str, str], key: bytes) -> Dict[str, str]:
    """Decrypt a single credential entry.

    Args:
        entry: A dictionary with base64‑encoded encrypted fields.
        key: Key used for decryption.

    Returns:
        A dictionary with decrypted plaintext values.
    """
    decrypted = {}
    for field, value in entry.items():
        cipher = base64.b64decode(value.encode())
        data = xor_bytes(cipher, key)
        decrypted[field] = data.decode()
    return decrypted


def load_store() -> Tuple[Dict[str, Dict[str, str]], str]:
    """Load the password store from disk.

    Returns:
        A tuple containing the decrypted store (or an empty dict) and the checksum.
    """
    if not os.path.exists(STORE_FILE):
        return {}, ""
    with open(STORE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("entries", {}), data.get("checksum", "")


def save_store(entries: Dict[str, Dict[str, str]]) -> None:
    """Save the password store to disk with a checksum.

    Args:
        entries: The encrypted entries to save.
    """
    # Compute a checksum to detect tampering
    serialized = json.dumps(entries, sort_keys=True).encode()
    checksum = hashlib.sha256(serialized).hexdigest()
    with open(STORE_FILE, "w", encoding="utf-8") as f:
        json.dump({"entries": entries, "checksum": checksum}, f, indent=2)


def verify_checksum(entries: Dict[str, Dict[str, str]], checksum: str) -> bool:
    """Verify the checksum of the stored data.

    Args:
        entries: The encrypted entries.
        checksum: The checksum saved in the file.

    Returns:
        True if the checksum matches, False otherwise.
    """
    serialized = json.dumps(entries, sort_keys=True).encode()
    expected = hashlib.sha256(serialized).hexdigest()
    return expected == checksum


def prompt_master_password() -> bytes:
    """Prompt the user for their master password and derive a key.

    Returns:
        A key derived from the master password.
    """
    master = getpass.getpass("Enter master password: ")
    return derive_key(master)


def add_entry(entries: Dict[str, Dict[str, str]], key: bytes) -> None:
    service = input("Service name: ").strip()
    if service in entries:
        print("An entry for that service already exists.")
        return
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    plain = {"service": service, "username": username, "password": password}
    entries[service] = encrypt_entry(plain, key)
    print(f"Credentials for '{service}' added.")


def list_services(entries: Dict[str, Dict[str, str]]) -> None:
    if not entries:
        print("No services stored yet.")
    else:
        print("Stored services:")
        for svc in entries.keys():
            print(f" - {svc}")


def get_credentials(entries: Dict[str, Dict[str, str]], key: bytes) -> None:
    service = input("Service name to retrieve: ").strip()
    if service not in entries:
        print("No entry found for that service.")
        return
    decrypted = decrypt_entry(entries[service], key)
    print(f"Service: {decrypted['service']}")
    print(f"Username: {decrypted['username']}")
    print(f"Password: {decrypted['password']}")


def menu() -> None:
    entries, checksum = load_store()
    key = prompt_master_password()
    if entries and not verify_checksum(entries, checksum):
        print("Warning: Password store integrity check failed. The file may have been tampered with!")
    while True:
        print("\nPassword Manager Menu")
        print("1. Add new credentials")
        print("2. List stored services")
        print("3. Retrieve credentials")
        print("4. Quit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            add_entry(entries, key)
            save_store(entries)
        elif choice == "2":
            list_services(entries)
        elif choice == "3":
            get_credentials(entries, key)
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid selection. Please choose 1-4.")


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nExiting.")
