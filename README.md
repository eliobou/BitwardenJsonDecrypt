# bwJsonDecryptor

Simple and minimal python script for decrypting bitwarden vaults exported as **password protected** json files (not account restricted json files, see https://bitwarden.com/help/encrypted-export/). Supports PBKDF2 and Argon2id. Note that json backups do not contain file attachments, sends, deleted vault items in the trash and shared items.

## Usage
```
python bwJsonDecryptor.py filename.json
```

## Output
After entering the password that was used to export the vault, the script prints the decrypted vault content to the terminal. It then interactively asks whether you want to save the decrypted content to a JSON file (default: no). If confirmed, the file is saved in the current directory as `bitwarden_export_decrypted_<timestamp>.json`. If you decline, nothing is written to disk.

## Dependencies
Requires packages ```cryptography``` and optionally ```argon2-cffi```.

## Changes from the original
- **Structured error handling**: a dedicated `DecryptionError` exception replaces scattered `print`+`sys.exit` calls, giving cleaner and more informative error messages (file not found, invalid JSON, bad KDF parameters, etc.).
- **Passphrase memory scrubbing**: the passphrase is held in a mutable `bytearray` and overwritten with zeros via `ctypes.memset` immediately after key derivation, regardless of whether decryption succeeds.
- **Constant-time MAC comparison**: uses `hmac.compare_digest` instead of `==` to prevent timing-based side-channel attacks.
- **Input validation**: KDF parameters are validated before use; Base64 decoding errors are caught and reported clearly.
- **Interactive export**: the `--write` flag has been replaced by a post-decryption prompt. The output file is now a `.json` file with a timestamp in its name instead of appending `.txt` to the input path.
- **Code quality**: refactored into typed, documented functions with a proper `main()` entry point.

## Testing
Tested with the export feature directly from vault.bitwarden.com (last tested with version 2026.5.0).

## Credit
Based on the code by https://github.com/g3bk47/bwJsonDecryptor, itself based on https://github.com/GurpreetKang/BitwardenDecrypt.
