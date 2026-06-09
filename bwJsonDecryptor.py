# Script for decrypting password-protected JSON files exported from Bitwarden vaults.
# Based on the code by https://github.com/g3bk47/bwJsonDecryptor

import base64
import ctypes
from datetime import datetime
import getpass
import hmac as hmac_stdlib
import json
import sys
from typing import Tuple

try:
    from cryptography.hazmat.backends              import default_backend
    from cryptography.hazmat.primitives            import ciphers, hashes, hmac, padding
    from cryptography.hazmat.primitives.ciphers    import algorithms, Cipher, modes
    from cryptography.hazmat.primitives.kdf.hkdf   import HKDFExpand
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ModuleNotFoundError:
    print("ERROR: package 'cryptography' is required. Run: pip install cryptography")
    sys.exit(1)


class DecryptionError(Exception):
    """Raised when decryption fails for any reason."""


def _zero_bytes(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros to minimize sensitive data in memory."""
    ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


def _derive_keys_pbkdf2(passphrase: bytes, salt: bytes, iterations: int) -> bytes:
    """Derive a 32-byte master key using PBKDF2-HMAC-SHA256."""
    kdf_engine = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf_engine.derive(passphrase)


def _derive_keys_argon2(
    passphrase: bytes,
    salt: bytes,
    iterations: int,
    memory_kb: int,
    parallelism: int,
) -> bytes:
    """Derive a 32-byte master key using Argon2id."""
    try:
        import argon2
    except ModuleNotFoundError:
        raise DecryptionError(
            "Package 'argon2-cffi' is required for this vault. Run: pip install argon2-cffi"
        )

    # Bitwarden hashes the salt with SHA-256 before passing it to Argon2
    digest = hashes.Hash(hashes.SHA256())
    digest.update(salt)
    salt_hash = digest.finalize()

    return argon2.low_level.hash_secret_raw(
        passphrase,
        salt=salt_hash,
        time_cost=iterations,
        memory_cost=memory_kb * 1024,
        parallelism=parallelism,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )


def get_keys(data: dict, passphrase: bytes) -> Tuple[bytes, bytes]:
    """
    Derive the AES encryption key and HMAC key from the vault metadata and passphrase.

    Args:
        data:       Parsed JSON content of the Bitwarden export file.
        passphrase: UTF-8-encoded user passphrase.

    Returns:
        A (enc_key, mac_key) tuple, each 32 bytes.

    Raises:
        DecryptionError: If the file is not encrypted, uses an unknown KDF,
                         or is missing required KDF parameters.
    """
    if not data.get("encrypted") or not data.get("passwordProtected"):
        raise DecryptionError("Input file is not encrypted or not password-protected.")

    salt = data["salt"].encode("utf-8")
    kdf_type = data.get("kdfType")

    if kdf_type == 0:  # PBKDF2
        iterations = data.get("kdfIterations")
        if not iterations:
            raise DecryptionError("Missing 'kdfIterations' field for PBKDF2.")
        master_key = _derive_keys_pbkdf2(passphrase, salt, iterations)

    elif kdf_type == 1:  # Argon2id
        required = ("kdfIterations", "kdfMemory", "kdfParallelism")
        missing = [k for k in required if k not in data]
        if missing:
            raise DecryptionError(f"Missing Argon2 parameter(s): {', '.join(missing)}")
        master_key = _derive_keys_argon2(
            passphrase,
            salt,
            data["kdfIterations"],
            data["kdfMemory"],
            data["kdfParallelism"],
        )

    else:
        raise DecryptionError(f"Unknown KDF type: {kdf_type!r}")

    enc_key = HKDFExpand(
        algorithm=hashes.SHA256(), length=32, info=b"enc", backend=default_backend()
    ).derive(master_key)
    mac_key = HKDFExpand(
        algorithm=hashes.SHA256(), length=32, info=b"mac", backend=default_backend()
    ).derive(master_key)

    return enc_key, mac_key


def decrypt(inp: str, enc_key: bytes, mac_key: bytes) -> str:
    """
    Decrypt a Bitwarden AES-256-CBC ciphertext string.

    The expected format is: "2.<base64-iv>|<base64-ciphertext>|<base64-mac>"

    Args:
        inp:     Encrypted string from the Bitwarden JSON export.
        enc_key: 32-byte AES encryption key.
        mac_key: 32-byte HMAC-SHA256 key.

    Returns:
        Decrypted plaintext as a UTF-8 string.

    Raises:
        DecryptionError: If the format is invalid or MAC verification fails.
    """
    parts = inp.split("|")
    if len(parts) != 3 or not parts[0].startswith("2."):
        raise DecryptionError(
            f"Unexpected ciphertext format (expected '2.<iv>|<data>|<mac>', got prefix {parts[0][:4]!r})."
        )

    try:
        iv        = base64.b64decode(parts[0][2:], validate=True)
        ciphertext = base64.b64decode(parts[1],    validate=True)
        mac        = base64.b64decode(parts[2],    validate=True)
    except Exception as exc:
        raise DecryptionError(f"Base64 decoding failed: {exc}") from exc

    # Compute expected MAC and compare in constant time to prevent timing attacks
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    h.update(ciphertext)
    expected_mac = h.finalize()

    if not hmac_stdlib.compare_digest(mac, expected_mac):
        raise DecryptionError(
            "MAC mismatch — wrong password or corrupted data."
        )

    cipher    = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python bwJsonDecryptor.py <export.json>")
        sys.exit(1)

    json_path = sys.argv[1]

    # Load the export file
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: file not found: {json_path}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON file: {exc}")
        sys.exit(1)

    # Read passphrase into a mutable bytearray so it can be zeroed afterward
    raw_passphrase = bytearray(
        getpass.getpass(prompt="Enter password: ").encode("utf-8")
    )

    try:
        enc_key, mac_key = get_keys(data, bytes(raw_passphrase))
    except DecryptionError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
    finally:
        _zero_bytes(raw_passphrase)  # Scrub passphrase from memory regardless of outcome

    try:
        validation = decrypt(data["encKeyValidation_DO_NOT_EDIT"], enc_key, mac_key)
        print("Info: encKeyValidation_DO_NOT_EDIT:", validation)

        vault = decrypt(data["data"], enc_key, mac_key)
    except DecryptionError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    print(vault)

    answer = input("\nExporter le vault déchiffré dans un fichier JSON ? [o/N] ").strip().lower()
    if answer == "o":
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_path = f"bitwarden_export_decrypted_{timestamp}.json"
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(vault)
            print(f"Info: vault déchiffré enregistré dans {output_path}")
        except OSError as exc:
            print(f"ERROR: impossible d'écrire le fichier de sortie : {exc}")
            sys.exit(1)


if __name__ == "__main__":
    main()