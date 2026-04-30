from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import os
from dataclasses import dataclass
from typing import Callable, Optional

import bcrypt
from argon2 import PasswordHasher
from blake3 import blake3
from colorama import Fore
from Crypto.Cipher import AES, ARC2, ARC4, Blowfish, CAST, ChaCha20, DES, DES3, Salsa20
from Crypto.Hash import CMAC, RIPEMD160
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms as crypto_algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.poly1305 import Poly1305
from gmssl import sm3
from gmssl.sm4 import CryptSM4, PKCS7, SM4_DECRYPT, SM4_ENCRYPT
from gostcrypto import gostcipher, gosthash


BANNER_LINE = "=" * 60
PASSWORD_HASHER = PasswordHasher()


@dataclass(frozen=True)
class MenuItem:
    label: str
    action: Callable[[], None]


def _prompt(text: str) -> str:
    return input(Fore.GREEN + text).strip()


def _pause() -> None:
    input(Fore.CYAN + "Press Enter to continue...")


def _print_error(message: str) -> None:
    print(Fore.RED + message)


def _print_ok(message: str) -> None:
    print(Fore.YELLOW + message)


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _derive_key(passphrase: str, length: int) -> bytes:
    salt = b"cryptography-toolkit"
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 100_000, dklen=length)


def _des3_key(passphrase: str) -> bytes:
    candidate = _derive_key(passphrase, 24)
    for _ in range(8):
        try:
            return DES3.adjust_key_parity(candidate)
        except ValueError:
            candidate = hashlib.sha256(candidate + b"!").digest()[:24]
    return DES3.adjust_key_parity(candidate)


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def _menu(title: str, items: list[MenuItem]) -> None:
    while True:
        print(Fore.CYAN + f"\n{BANNER_LINE}")
        print(Fore.CYAN + title)
        print(Fore.CYAN + BANNER_LINE)
        for index, item in enumerate(items, start=1):
            print(Fore.YELLOW + f"{index}. {item.label}")
        print(Fore.YELLOW + "0. Back")
        choice = _prompt("Select an option: ")
        if choice == "0":
            return
        if choice.isdigit() and 1 <= int(choice) <= len(items):
            items[int(choice) - 1].action()
        else:
            _print_error("Invalid option! Try again.")


def _unsupported(name: str, reason: str) -> Callable[[], None]:
    def handler() -> None:
        _print_error(f"{name} is not available in this build: {reason}")
        _pause()

    return handler


def _cryptography_algorithm(name: str):
    return getattr(crypto_algorithms, name, None)


def _pycryptodome_block_roundtrip(cipher_module, key_len: int, block_size: int, key_builder: Callable[[str], bytes]) -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    passphrase = _prompt("Enter the passphrase: ")
    if choice == "e":
        text = _prompt("Enter the plaintext: ")
        key = key_builder(passphrase)
        iv = os.urandom(block_size)
        kwargs = {"iv": iv}
        if cipher_module is ARC2:
            kwargs["effective_keylen"] = min(len(key) * 8, 1024)
        cipher = cipher_module.new(key, cipher_module.MODE_CBC, **kwargs)
        ciphertext = cipher.encrypt(_pkcs7_pad(text.encode("utf-8"), block_size))
        print(Fore.YELLOW + "Ciphertext (base64): " + Fore.MAGENTA + _encode(iv + ciphertext))
        _pause()
        return
    if choice == "d":
        payload = _prompt("Enter the base64 payload: ")
        key = key_builder(passphrase)
        raw = _decode(payload)
        iv, ciphertext = raw[:block_size], raw[block_size:]
        kwargs = {"iv": iv}
        if cipher_module is ARC2:
            kwargs["effective_keylen"] = min(len(key) * 8, 1024)
        cipher = cipher_module.new(key, cipher_module.MODE_CBC, **kwargs)
        plaintext = _pkcs7_unpad(cipher.decrypt(ciphertext), block_size).decode("utf-8", errors="replace")
        print(Fore.YELLOW + "Plaintext: " + Fore.MAGENTA + plaintext)
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _cryptography_block_roundtrip(algorithm_cls, key_len: int, block_size: int) -> None:
    if algorithm_cls is None:
        _print_error("This cipher is not supported by the installed cryptography backend.")
        _pause()
        return
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    passphrase = _prompt("Enter the passphrase: ")
    key = _derive_key(passphrase, key_len)
    if choice == "e":
        text = _prompt("Enter the plaintext: ")
        iv = os.urandom(block_size)
        cipher = Cipher(algorithm_cls(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(_pkcs7_pad(text.encode("utf-8"), block_size)) + encryptor.finalize()
        print(Fore.YELLOW + "Ciphertext (base64): " + Fore.MAGENTA + _encode(iv + ciphertext))
        _pause()
        return
    if choice == "d":
        payload = _prompt("Enter the base64 payload: ")
        raw = _decode(payload)
        iv, ciphertext = raw[:block_size], raw[block_size:]
        cipher = Cipher(algorithm_cls(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = _pkcs7_unpad(decryptor.update(ciphertext) + decryptor.finalize(), block_size).decode("utf-8", errors="replace")
        print(Fore.YELLOW + "Plaintext: " + Fore.MAGENTA + plaintext)
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _stream_roundtrip(cipher_module, key_len: int, nonce_len: int = 8) -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    passphrase = _prompt("Enter the passphrase: ")
    key = _derive_key(passphrase, key_len)
    if choice == "e":
        text = _prompt("Enter the plaintext: ")
        if cipher_module is ARC4:
            cipher = cipher_module.new(key)
            ciphertext = cipher.encrypt(text.encode("utf-8"))
            print(Fore.YELLOW + "Ciphertext (base64): " + Fore.MAGENTA + _encode(ciphertext))
            _pause()
            return
        nonce = os.urandom(nonce_len)
        cipher = cipher_module.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(text.encode("utf-8"))
        print(Fore.YELLOW + "Ciphertext (base64): " + Fore.MAGENTA + _encode(nonce + ciphertext))
        _pause()
        return
    if choice == "d":
        payload = _prompt("Enter the base64 payload: ")
        raw = _decode(payload)
        if cipher_module is ARC4:
            ciphertext = raw
            cipher = cipher_module.new(key)
            plaintext = cipher.decrypt(ciphertext).decode("utf-8", errors="replace")
            print(Fore.YELLOW + "Plaintext: " + Fore.MAGENTA + plaintext)
            _pause()
            return
        nonce, ciphertext = raw[:nonce_len], raw[nonce_len:]
        cipher = cipher_module.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext).decode("utf-8", errors="replace")
        print(Fore.YELLOW + "Plaintext: " + Fore.MAGENTA + plaintext)
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _sm4_roundtrip() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    passphrase = _prompt("Enter the passphrase: ")
    key = _derive_key(passphrase, 16)
    if choice == "e":
        text = _prompt("Enter the plaintext: ")
        iv = os.urandom(16)
        cipher = CryptSM4(padding_mode=PKCS7)
        cipher.set_key(key, SM4_ENCRYPT)
        ciphertext = cipher.crypt_cbc(iv, text.encode("utf-8"))
        print(Fore.YELLOW + "Ciphertext (base64): " + Fore.MAGENTA + _encode(iv + ciphertext))
        _pause()
        return
    if choice == "d":
        payload = _prompt("Enter the base64 payload: ")
        raw = _decode(payload)
        iv, ciphertext = raw[:16], raw[16:]
        cipher = CryptSM4(padding_mode=PKCS7)
        cipher.set_key(key, SM4_DECRYPT)
        plaintext = cipher.crypt_cbc(iv, ciphertext).decode("utf-8", errors="replace")
        print(Fore.YELLOW + "Plaintext: " + Fore.MAGENTA + plaintext)
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _gost_roundtrip() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    passphrase = _prompt("Enter the passphrase: ")
    key = bytearray(_derive_key(passphrase, 32))
    if choice == "e":
        text = _prompt("Enter the plaintext: ")
        iv = bytearray(os.urandom(8))
        cipher = gostcipher.new("magma", key, gostcipher.MODE_CBC, iv=iv)
        ciphertext = bytes(cipher.encrypt(text.encode("utf-8")))
        print(Fore.YELLOW + "Ciphertext (base64): " + Fore.MAGENTA + _encode(bytes(iv) + ciphertext))
        _pause()
        return
    if choice == "d":
        payload = _prompt("Enter the base64 payload: ")
        raw = _decode(payload)
        iv, ciphertext = bytearray(raw[:8]), raw[8:]
        cipher = gostcipher.new("magma", key, gostcipher.MODE_CBC, iv=iv)
        plaintext = bytes(cipher.decrypt(ciphertext)).rstrip(b"\x00").decode("utf-8", errors="replace")
        print(Fore.YELLOW + "Plaintext: " + Fore.MAGENTA + plaintext)
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _hash_string(label: str, digest_fn: Callable[[bytes], str]) -> None:
    text = _prompt(f"Enter text for {label}: ")
    print(Fore.YELLOW + f"{label}: " + Fore.MAGENTA + digest_fn(text.encode("utf-8")))
    _pause()


def _hash_hashlib(name: str) -> Callable[[bytes], str]:
    def digest(data: bytes) -> str:
        return hashlib.new(name, data).hexdigest()

    return digest


def _hash_blake2b(data: bytes) -> str:
    return hashlib.blake2b(data).hexdigest()


def _hash_blake2s(data: bytes) -> str:
    return hashlib.blake2s(data).hexdigest()


def _hash_ripemd160(data: bytes) -> str:
    return RIPEMD160.new(data=data).hexdigest()


def _hash_b3(data: bytes) -> str:
    return blake3(data).hexdigest()


def _hash_sm3(data: bytes) -> str:
    return sm3.sm3_hash(sm3.bytes_to_list(data))


def _hash_streebog(name: str) -> Callable[[bytes], str]:
    def digest(data: bytes) -> str:
        hasher = gosthash.new(name)
        hasher.update(data)
        return hasher.hexdigest()

    return digest


def _password_hash_bcrypt() -> None:
    mode = _prompt("Do you want to (H)ash or (V)erify? ").lower()
    password = _prompt("Enter the password: ")
    if mode == "h":
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        print(Fore.YELLOW + "bcrypt hash: " + Fore.MAGENTA + hashed.decode("ascii"))
        _pause()
        return
    if mode == "v":
        stored = _prompt("Enter the stored bcrypt hash: ")
        print(Fore.YELLOW + ("Verified" if bcrypt.checkpw(password.encode("utf-8"), stored.encode("ascii")) else "Not verified"))
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _password_hash_scrypt() -> None:
    mode = _prompt("Do you want to (H)ash or (V)erify? ").lower()
    password = _prompt("Enter the password: ")
    n = 2**14
    r = 8
    p = 1
    if mode == "h":
        salt = os.urandom(16)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=64)
        encoded = f"scrypt${n}${r}${p}${_encode(salt)}${_encode(digest)}"
        print(Fore.YELLOW + "scrypt hash: " + Fore.MAGENTA + encoded)
        _pause()
        return
    if mode == "v":
        stored = _prompt("Enter the stored scrypt hash: ")
        try:
            _, n_text, r_text, p_text, salt_text, digest_text = stored.split("$", 5)
            salt = _decode(salt_text)
            digest = _decode(digest_text)
            candidate = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=int(n_text),
                r=int(r_text),
                p=int(p_text),
                dklen=len(digest),
            )
            print(Fore.YELLOW + ("Verified" if hmac.compare_digest(candidate, digest) else "Not verified"))
        except Exception:
            _print_error("Invalid stored scrypt format.")
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _password_hash_argon2() -> None:
    mode = _prompt("Do you want to (H)ash or (V)erify? ").lower()
    password = _prompt("Enter the password: ")
    if mode == "h":
        hashed = PASSWORD_HASHER.hash(password)
        print(Fore.YELLOW + "Argon2 hash: " + Fore.MAGENTA + hashed)
        _pause()
        return
    if mode == "v":
        stored = _prompt("Enter the stored Argon2 hash: ")
        try:
            ok = PASSWORD_HASHER.verify(stored, password)
            print(Fore.YELLOW + ("Verified" if ok else "Not verified"))
        except Exception:
            _print_error("Invalid Argon2 hash or password.")
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _password_hash_pbkdf2() -> None:
    mode = _prompt("Do you want to (H)ash or (V)erify? ").lower()
    password = _prompt("Enter the password: ")
    iterations = 310_000
    if mode == "h":
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
        encoded = f"pbkdf2$sha256${iterations}${_encode(salt)}${_encode(digest)}"
        print(Fore.YELLOW + "PBKDF2 hash: " + Fore.MAGENTA + encoded)
        _pause()
        return
    if mode == "v":
        stored = _prompt("Enter the stored PBKDF2 hash: ")
        try:
            _, hash_name, iter_text, salt_text, digest_text = stored.split("$", 4)
            salt = _decode(salt_text)
            digest = _decode(digest_text)
            candidate = hashlib.pbkdf2_hmac(
                hash_name,
                password.encode("utf-8"),
                salt,
                int(iter_text),
                dklen=len(digest),
            )
            print(Fore.YELLOW + ("Verified" if hmac.compare_digest(candidate, digest) else "Not verified"))
        except Exception:
            _print_error("Invalid stored PBKDF2 format.")
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _hmac_demo() -> None:
    text = _prompt("Enter the message: ")
    algorithm = _prompt("Hash function [sha256]: ").strip().lower() or "sha256"
    key = _derive_key(_prompt("Enter the secret key: "), 32)
    digest = hmac.new(key, text.encode("utf-8"), getattr(hashlib, algorithm)).hexdigest()
    print(Fore.YELLOW + "HMAC: " + Fore.MAGENTA + digest)
    _pause()


def _cmac_demo() -> None:
    text = _prompt("Enter the message: ")
    key = _derive_key(_prompt("Enter the secret key: "), 16)
    mac = CMAC.new(key, ciphermod=AES)
    mac.update(text.encode("utf-8"))
    print(Fore.YELLOW + "CMAC: " + Fore.MAGENTA + mac.hexdigest())
    _pause()


def _gmac_demo() -> None:
    text = _prompt("Enter the message: ")
    aad = _prompt("Enter associated data (optional): ")
    key = _derive_key(_prompt("Enter the secret key: "), 32)
    nonce = os.urandom(12)
    tag = AESGCM(key).encrypt(nonce, b"", aad.encode("utf-8") + text.encode("utf-8"))
    print(Fore.YELLOW + "GMAC (base64 nonce+tag): " + Fore.MAGENTA + _encode(nonce + tag))
    _pause()


def _poly1305_demo() -> None:
    text = _prompt("Enter the message: ")
    key = _derive_key(_prompt("Enter the secret key: "), 32)
    tag = Poly1305.generate_tag(key, text.encode("utf-8"))
    print(Fore.YELLOW + "Poly1305 tag (base64): " + Fore.MAGENTA + _encode(tag))
    _pause()


def _aead_demo(name: str) -> None:
    message = _prompt("Enter the plaintext: ")
    aad = _prompt("Enter associated data (optional): ")
    passphrase = _prompt("Enter the passphrase: ")
    if name == "AES-GCM":
        key = _derive_key(passphrase, 32)
        nonce = os.urandom(12)
        aead = AESGCM(key)
    elif name == "AES-CCM":
        key = _derive_key(passphrase, 32)
        nonce = os.urandom(13)
        aead = AESCCM(key)
    elif name == "ChaCha20-Poly1305":
        key = _derive_key(passphrase, 32)
        nonce = os.urandom(12)
        aead = ChaCha20Poly1305(key)
    else:
        _print_error("Unsupported AEAD mode.")
        _pause()
        return
    ciphertext = aead.encrypt(nonce, message.encode("utf-8"), aad.encode("utf-8"))
    print(Fore.YELLOW + "Ciphertext (base64): " + Fore.MAGENTA + _encode(nonce + ciphertext))
    recovered = aead.decrypt(nonce, ciphertext, aad.encode("utf-8")).decode("utf-8", errors="replace")
    print(Fore.YELLOW + "Recovered plaintext: " + Fore.MAGENTA + recovered)
    _pause()


def _rsa_demo() -> None:
    action = _prompt("Do you want to (E)ncrypt or (S)ign? ").lower()
    message = _prompt("Enter the message: ").encode("utf-8")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    if action == "e":
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=crypto_hashes.SHA256()),
                algorithm=crypto_hashes.SHA256(),
                label=None,
            ),
        )
        recovered = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=crypto_hashes.SHA256()),
                algorithm=crypto_hashes.SHA256(),
                label=None,
            ),
        )
        print(Fore.YELLOW + "Ciphertext (base64): " + Fore.MAGENTA + _encode(ciphertext))
        print(Fore.YELLOW + "Recovered: " + Fore.MAGENTA + recovered.decode("utf-8", errors="replace"))
        _pause()
        return
    if action == "s":
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=crypto_hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            crypto_hashes.SHA256(),
        )
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(algorithm=crypto_hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                crypto_hashes.SHA256(),
            )
            verified = True
        except InvalidSignature:
            verified = False
        print(Fore.YELLOW + "Signature (base64): " + Fore.MAGENTA + _encode(signature))
        print(Fore.YELLOW + f"Verified: {verified}")
        _pause()
        return
    _print_error("Invalid choice!")
    _pause()


def _dsa_demo() -> None:
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    message = _prompt("Enter the message to sign: ").encode("utf-8")
    signature = private_key.sign(message, crypto_hashes.SHA256())
    try:
        public_key.verify(signature, message, crypto_hashes.SHA256())
        verified = True
    except InvalidSignature:
        verified = False
    print(Fore.YELLOW + "Signature (base64): " + Fore.MAGENTA + _encode(signature))
    print(Fore.YELLOW + f"Verified: {verified}")
    _pause()


def _ecdsa_demo() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    message = _prompt("Enter the message to sign: ").encode("utf-8")
    signature = private_key.sign(message, ec.ECDSA(crypto_hashes.SHA256()))
    try:
        public_key.verify(signature, message, ec.ECDSA(crypto_hashes.SHA256()))
        verified = True
    except InvalidSignature:
        verified = False
    print(Fore.YELLOW + "Signature (base64): " + Fore.MAGENTA + _encode(signature))
    print(Fore.YELLOW + f"Verified: {verified}")
    _pause()


def _dh_demo() -> None:
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    alice_private = parameters.generate_private_key()
    bob_private = parameters.generate_private_key()
    alice_shared = alice_private.exchange(bob_private.public_key())
    bob_shared = bob_private.exchange(alice_private.public_key())
    print(Fore.YELLOW + "Shared secret match: " + Fore.MAGENTA + str(alice_shared == bob_shared))
    print(Fore.YELLOW + "Shared secret (base64): " + Fore.MAGENTA + _encode(alice_shared))
    _pause()


def _ecdh_demo() -> None:
    private_a = ec.generate_private_key(ec.SECP256R1())
    private_b = ec.generate_private_key(ec.SECP256R1())
    shared_a = private_a.exchange(ec.ECDH(), private_b.public_key())
    shared_b = private_b.exchange(ec.ECDH(), private_a.public_key())
    print(Fore.YELLOW + "Shared secret match: " + Fore.MAGENTA + str(shared_a == shared_b))
    print(Fore.YELLOW + "Shared secret (base64): " + Fore.MAGENTA + _encode(shared_a))
    _pause()


def _eddsa_demo(kind: str) -> None:
    message = _prompt("Enter the message to sign: ").encode("utf-8")
    if kind == "Ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        private_key = ed448.Ed448PrivateKey.generate()
    public_key = private_key.public_key()
    signature = private_key.sign(message)
    try:
        public_key.verify(signature, message)
        verified = True
    except InvalidSignature:
        verified = False
    print(Fore.YELLOW + "Signature (base64): " + Fore.MAGENTA + _encode(signature))
    print(Fore.YELLOW + f"Verified: {verified}")
    _pause()


def _pqc_kem_demo(module_name: str, label: str) -> None:
    module = importlib.import_module(f"pqcrypto.kem.{module_name}")
    public_key, private_key = module.generate_keypair()
    ciphertext, shared_a = module.encrypt(public_key)
    shared_b = module.decrypt(private_key, ciphertext)
    print(Fore.YELLOW + f"{label} shared secret match: " + Fore.MAGENTA + str(shared_a == shared_b))
    print(Fore.YELLOW + "Shared secret (base64): " + Fore.MAGENTA + _encode(shared_a))
    _pause()


def _pqc_sign_demo(module_name: str, label: str) -> None:
    module = importlib.import_module(f"pqcrypto.sign.{module_name}")
    public_key, private_key = module.generate_keypair()
    message = _prompt("Enter the message to sign: ").encode("utf-8")
    signature = module.sign(private_key, message)
    verified = module.verify(public_key, message, signature)
    print(Fore.YELLOW + f"{label} signature (base64): " + Fore.MAGENTA + _encode(signature))
    print(Fore.YELLOW + f"Verified: {verified}")
    _pause()


def _caesar_cipher(text: str, shift: int, encrypt: bool = True) -> str:
    if not encrypt:
        shift = -shift
    result = []
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
        elif char.islower():
            result.append(chr((ord(char) - 97 + shift) % 26 + 97))
        else:
            result.append(char)
    return "".join(result)


def _atbash_cipher(text: str) -> str:
    result = []
    for char in text:
        if char.isupper():
            result.append(chr(90 - (ord(char) - 65)))
        elif char.islower():
            result.append(chr(122 - (ord(char) - 97)))
        else:
            result.append(char)
    return "".join(result)


def _affine_cipher(text: str, a: int, b: int, encrypt: bool = True) -> str:
    result = []
    for char in text:
        if char.isupper():
            x = ord(char) - 65
            if encrypt:
                c = (a * x + b) % 26
            else:
                try:
                    a_inv = pow(a, -1, 26)
                    c = (a_inv * (x - b)) % 26
                except ValueError:
                    _print_error("'a' must be coprime with 26")
                    return text
            result.append(chr(c + 65))
        elif char.islower():
            x = ord(char) - 97
            if encrypt:
                c = (a * x + b) % 26
            else:
                try:
                    a_inv = pow(a, -1, 26)
                    c = (a_inv * (x - b)) % 26
                except ValueError:
                    _print_error("'a' must be coprime with 26")
                    return text
            result.append(chr(c + 97))
        else:
            result.append(char)
    return "".join(result)


def _vigenere_cipher(text: str, key: str, encrypt: bool = True) -> str:
    key = key.upper()
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            if char.isupper():
                c = chr((ord(char) - 65 + (shift if encrypt else -shift)) % 26 + 65)
            else:
                c = chr((ord(char) - 97 + (shift if encrypt else -shift)) % 26 + 97)
            result.append(c)
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def _autokey_cipher(text: str, key: str, encrypt: bool = True) -> str:
    key = key.upper()
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            if key_index < len(key):
                shift = ord(key[key_index]) - 65
            else:
                if encrypt:
                    shift = ord(text[key_index - len(key)].upper()) - 65
                else:
                    shift = ord(result[key_index - len(key)].upper()) - 65
            if char.isupper():
                c = chr((ord(char) - 65 + (shift if encrypt else -shift)) % 26 + 65)
            else:
                c = chr((ord(char) - 97 + (shift if encrypt else -shift)) % 26 + 97)
            result.append(c)
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def _playfair_cipher(text: str, key: str, encrypt: bool = True) -> str:
    key = (key + "ABCDEFGHIJKLMNOPQRSTUVWXYZ").upper().replace("J", "I")
    matrix = []
    seen = set()
    for char in key:
        if char.isalpha() and char not in seen and char != "J":
            matrix.append(char)
            seen.add(char)
    while len(matrix) < 25:
        for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if char not in seen and char != "J":
                matrix.append(char)
                seen.add(char)
                if len(matrix) == 25:
                    break
    matrix_dict = {char: (i // 5, i % 5) for i, char in enumerate(matrix)}
    text = text.upper().replace("J", "I").replace(" ", "")
    pairs = []
    i = 0
    while i < len(text):
        if i + 1 < len(text):
            if text[i] == text[i + 1]:
                pairs.append(text[i] + "X")
                i += 1
            else:
                pairs.append(text[i:i + 2])
                i += 2
        else:
            pairs.append(text[i] + "X")
            i += 1
    result = []
    for pair in pairs:
        r1, c1 = matrix_dict[pair[0]]
        r2, c2 = matrix_dict[pair[1]]
        if r1 == r2:
            c1 = (c1 + (1 if encrypt else -1)) % 5
            c2 = (c2 + (1 if encrypt else -1)) % 5
        elif c1 == c2:
            r1 = (r1 + (1 if encrypt else -1)) % 5
            r2 = (r2 + (1 if encrypt else -1)) % 5
        else:
            c1, c2 = c2, c1
        result.append(matrix[r1 * 5 + c1])
        result.append(matrix[r2 * 5 + c2])
    return "".join(result)


def _rail_fence_cipher(text: str, rails: int, encrypt: bool = True) -> str:
    if rails < 2:
        return text
    text = text.replace(" ", "")
    if encrypt:
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        return "".join("".join(rail) for rail in fence)
    else:
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for _ in range(len(text)):
            fence[rail].append(None)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        idx = 0
        for i in range(rails):
            for j in range(len(fence[i])):
                fence[i][j] = text[idx]
                idx += 1
        result = []
        rail = 0
        direction = 1
        for _ in range(len(text)):
            result.append(fence[rail].pop(0))
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        return "".join(result)


def _columnar_transposition_cipher(text: str, key: str, encrypt: bool = True) -> str:
    text = text.replace(" ", "").upper()
    key = key.upper()
    if encrypt:
        key_order = sorted(range(len(key)), key=lambda i: key[i])
        cols = [[] for _ in range(len(key))]
        for i, char in enumerate(text):
            cols[i % len(key)].append(char)
        result = ""
        for idx in key_order:
            result += "".join(cols[idx])
        return result
    else:
        key_order = sorted(range(len(key)), key=lambda i: key[i])
        num_cols = len(key)
        num_rows = (len(text) + num_cols - 1) // num_cols
        cols = [[] for _ in range(num_cols)]
        idx = 0
        for order_pos in key_order:
            col_len = (len(text) + num_cols - 1 - order_pos) // num_cols if order_pos < len(text) % num_cols else len(text) // num_cols
            for i in range(num_rows):
                if idx < len(text):
                    cols[order_pos].append(text[idx])
                    idx += 1
        result = ""
        for row in range(num_rows):
            for col in range(num_cols):
                if row < len(cols[col]):
                    result += cols[col][row]
        return result


def _scytale_cipher(text: str, turns: int, encrypt: bool = True) -> str:
    text = text.replace(" ", "").upper()
    if encrypt:
        rows = len(text) // turns
        cols = turns
        result = ""
        for col in range(cols):
            for row in range(rows):
                if row * cols + col < len(text):
                    result += text[row * cols + col]
        return result
    else:
        cols = len(text) // turns
        rows = turns
        result = ""
        for row in range(rows):
            for col in range(cols):
                if col * rows + row < len(text):
                    result += text[col * rows + row]
        return result


def _bacon_cipher(text: str, encrypt: bool = True) -> str:
    alphabet_to_bacon = {
        'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
        'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
        'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
        'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
        'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA',
        'Z': 'BBAAB'
    }
    bacon_to_alphabet = {v: k for k, v in alphabet_to_bacon.items()}
    text = text.upper().replace(" ", "")
    if encrypt:
        return "".join(alphabet_to_bacon.get(char, "") for char in text)
    else:
        result = ""
        for i in range(0, len(text), 5):
            result += bacon_to_alphabet.get(text[i:i + 5], "?")
        return result


def _polybius_square_cipher(text: str, encrypt: bool = True) -> str:
    polybius_map = {
        'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15',
        'F': '21', 'G': '22', 'H': '23', 'I': '24', 'J': '24',
        'K': '25', 'L': '31', 'M': '32', 'N': '33', 'O': '34',
        'P': '35', 'Q': '41', 'R': '42', 'S': '43', 'T': '44',
        'U': '45', 'V': '51', 'W': '52', 'X': '53', 'Y': '54',
        'Z': '55'
    }
    reverse_polybius = {v: k for k, v in polybius_map.items()}
    text = text.upper().replace(" ", "")
    if encrypt:
        return "".join(polybius_map.get(char, "") for char in text)
    else:
        result = ""
        for i in range(0, len(text), 2):
            result += reverse_polybius.get(text[i:i + 2], "?")
        return result


def _pigpen_cipher(text: str) -> str:
    pigpen_map = {
        'A': '🔲', 'B': '⬜', 'C': '🔳', 'D': '⬛', 'E': '◼', 'F': '◻',
        'G': '◾', 'H': '◽', 'I': '▪', 'J': '▫', 'K': '▬', 'L': '▭',
        'M': '█', 'N': '░', 'O': '▓', 'P': '▒', 'Q': 'Ⓐ', 'R': 'Ⓑ',
        'S': 'Ⓒ', 'T': 'Ⓓ', 'U': 'Ⓔ', 'V': 'Ⓕ', 'W': 'Ⓖ', 'X': 'Ⓗ',
        'Y': 'Ⓘ', 'Z': 'Ⓙ'
    }
    return "".join(pigpen_map.get(char.upper(), char) for char in text)


def _bifid_cipher(text: str, key: str, encrypt: bool = True) -> str:
    key = (key + "ABCDEFGHIJKLMNOPQRSTUVWXYZ").upper().replace("J", "I")
    matrix = []
    seen = set()
    for char in key:
        if char.isalpha() and char not in seen and char != "J":
            matrix.append(char)
            seen.add(char)
    while len(matrix) < 25:
        for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if char not in seen and char != "J":
                matrix.append(char)
                seen.add(char)
                if len(matrix) == 25:
                    break
    matrix_dict = {char: (i // 5, i % 5) for i, char in enumerate(matrix)}
    reverse_dict = {v: k for k, v in matrix_dict.items()}
    text = text.upper().replace("J", "I").replace(" ", "")
    if encrypt:
        rows = []
        cols = []
        for char in text:
            r, c = matrix_dict[char]
            rows.append(str(r))
            cols.append(str(c))
        combined = rows + cols
        result = ""
        for i in range(0, len(combined), 2):
            if i + 1 < len(combined):
                r = int(combined[i])
                c = int(combined[i + 1])
                result += reverse_dict.get((r, c), "?")
        return result
    else:
        half = len(text)
        rows = [int(x) for x in text[:half]]
        cols = [int(x) for x in text[half:]]
        result = ""
        for i in range(len(rows)):
            result += reverse_dict.get((rows[i], cols[i]), "?")
        return result


def _one_time_pad(text: str, key: str, encrypt: bool = True) -> str:
    text = text.upper()
    key = key.upper()
    result = []
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - 65
            if encrypt:
                c = chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                c = chr((ord(char) - 65 - shift) % 26 + 65)
            result.append(c)
        else:
            result.append(char)
    return "".join(result)


def _caesar_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    try:
        shift = int(_prompt("Enter the shift key (number): "))
    except ValueError:
        _print_error("Shift must be a number.")
        _pause()
        return
    result = _caesar_cipher(text, shift, encrypt=(choice == "e"))
    if choice in {"e", "d"}:
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _atbash_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    if choice in {"e", "d"}:
        result = _atbash_cipher(text)
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _affine_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    try:
        a = int(_prompt("Enter coefficient 'a' (must be coprime with 26): "))
        b = int(_prompt("Enter coefficient 'b': "))
    except ValueError:
        _print_error("Coefficients must be numbers.")
        _pause()
        return
    result = _affine_cipher(text, a, b, encrypt=(choice == "e"))
    print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    _pause()


def _vigenere_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    key = _prompt("Enter the key: ")
    if choice in {"e", "d"}:
        result = _vigenere_cipher(text, key, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _autokey_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    key = _prompt("Enter the initial key: ")
    if choice in {"e", "d"}:
        result = _autokey_cipher(text, key, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _playfair_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    key = _prompt("Enter the key: ")
    if choice in {"e", "d"}:
        result = _playfair_cipher(text, key, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _rail_fence_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    try:
        rails = int(_prompt("Enter the number of rails: "))
    except ValueError:
        _print_error("Rails must be a number.")
        _pause()
        return
    if choice in {"e", "d"}:
        result = _rail_fence_cipher(text, rails, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _columnar_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    key = _prompt("Enter the key: ")
    if choice in {"e", "d"}:
        result = _columnar_transposition_cipher(text, key, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _scytale_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    try:
        turns = int(_prompt("Enter the number of turns: "))
    except ValueError:
        _print_error("Turns must be a number.")
        _pause()
        return
    if choice in {"e", "d"}:
        result = _scytale_cipher(text, turns, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _bacon_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    if choice in {"e", "d"}:
        result = _bacon_cipher(text, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _polybius_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    if choice in {"e", "d"}:
        result = _polybius_square_cipher(text, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _bifid_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    key = _prompt("Enter the key: ")
    if choice in {"e", "d"}:
        result = _bifid_cipher(text, key, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _otp_demo() -> None:
    choice = _prompt("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    text = _prompt("Enter the text: ")
    key = _prompt("Enter the one-time pad key: ")
    if choice in {"e", "d"}:
        result = _one_time_pad(text, key, encrypt=(choice == "e"))
        print(Fore.YELLOW + "Result: " + Fore.MAGENTA + result)
    else:
        _print_error("Invalid choice!")
    _pause()


def _pigpen_demo() -> None:
    text = _prompt("Enter the text to encode in Pigpen: ")
    result = _pigpen_cipher(text)
    print(Fore.YELLOW + "Pigpen (symbolic): " + Fore.MAGENTA + result)
    _pause()


def _substitution_items() -> list[MenuItem]:
    return [
        MenuItem("Caesar Cipher", _caesar_demo),
        MenuItem("Atbash Cipher", _atbash_demo),
        MenuItem("Affine Cipher", _affine_demo),
        MenuItem("Vigenère Cipher", _vigenere_demo),
        MenuItem("Autokey Cipher", _autokey_demo),
        MenuItem("Playfair Cipher", _playfair_demo),
        MenuItem("Beaufort Cipher", _unsupported("Beaufort Cipher", "complex variant of Vigenère; see Autokey/Vigenère")),
        MenuItem("Gronsfeld Cipher", _unsupported("Gronsfeld Cipher", "variant of Vigenère with numeric key")),
        MenuItem("Hill Cipher", _unsupported("Hill Cipher", "requires matrix math; educational implementation omitted")),
        MenuItem("Four-Square Cipher", _unsupported("Four-Square Cipher", "advanced variant; see Playfair")),
        MenuItem("Two-Square Cipher", _unsupported("Two-Square Cipher", "advanced variant; see Playfair")),
        MenuItem("Simple Substitution", _unsupported("Simple Substitution", "requires full substitution table input")),
    ]


def _transposition_items() -> list[MenuItem]:
    return [
        MenuItem("Rail Fence Cipher", _rail_fence_demo),
        MenuItem("Scytale Cipher", _scytale_demo),
        MenuItem("Columnar Transposition", _unsupported("Columnar Transposition", "complex reconstruction logic; see Rail Fence for similar transposition")),
        MenuItem("Double Transposition", _unsupported("Double Transposition", "apply Rail Fence twice; see Rail Fence")),
        MenuItem("Route Cipher", _unsupported("Route Cipher", "requires specific path definition")),
    ]


def _fractionation_items() -> list[MenuItem]:
    return [
        MenuItem("Bacon's Cipher (A/B)", _bacon_demo),
        MenuItem("Polybius Square", _polybius_demo),
        MenuItem("Nihilist Cipher", _unsupported("Nihilist Cipher", "variant of Polybius + transposition")),
    ]


def _product_items() -> list[MenuItem]:
    return [
        MenuItem("ADFGVX Cipher", _unsupported("ADFGVX Cipher", "WWI-era; complex fractionation+transposition")),
        MenuItem("ADFGX Cipher", _unsupported("ADFGX Cipher", "WWI-era variant; see ADFGVX")),
        MenuItem("Bifid Cipher", _unsupported("Bifid Cipher", "complex matrix reconstruction; educational interest")),
        MenuItem("Trifid Cipher", _unsupported("Trifid Cipher", "extends Bifid to 3-way split")),
    ]


def _mechanical_items() -> list[MenuItem]:
    return [
        MenuItem("Enigma Machine", _unsupported("Enigma Machine", "historical simulator too complex; see academic implementations")),
        MenuItem("Lorenz Cipher", _unsupported("Lorenz Cipher", "WWII stream cipher; historical interest")),
        MenuItem("Jefferson Disk", _unsupported("Jefferson Disk", "requires physical simulation; see transposition ciphers")),
    ]


def _other_classical_items() -> list[MenuItem]:
    return [
        MenuItem("Pigpen / Masonic Cipher", _pigpen_demo),
        MenuItem("Book Cipher", _unsupported("Book Cipher", "requires external text source")),
        MenuItem("Running Key Cipher", _unsupported("Running Key Cipher", "variant of Vigenère using book text")),
        MenuItem("One-Time Pad (Vernam)", _otp_demo),
    ]


def _supported_block_items() -> list[MenuItem]:
    camellia = _cryptography_algorithm("Camellia")
    idea = _cryptography_algorithm("IDEA")
    seed = _cryptography_algorithm("SEED")
    cast5 = _cryptography_algorithm("CAST5")
    blowfish_crypto = _cryptography_algorithm("Blowfish")
    triples = _cryptography_algorithm("TripleDES")
    aes_crypto = _cryptography_algorithm("AES")
    return [
        MenuItem("AES (Advanced Encryption Standard)", lambda: _pycryptodome_block_roundtrip(AES, 32, 16, lambda p: _derive_key(p, 32))),
        MenuItem("DES (Data Encryption Standard) (obsolete)", lambda: _pycryptodome_block_roundtrip(DES, 8, 8, lambda p: _derive_key(p, 8))),
        MenuItem("3DES (Triple DES)", lambda: _pycryptodome_block_roundtrip(DES3, 24, 8, _des3_key)),
        MenuItem("Blowfish", lambda: _pycryptodome_block_roundtrip(Blowfish, 16, 8, lambda p: _derive_key(p, 16))),
        MenuItem("RC2", lambda: _pycryptodome_block_roundtrip(ARC2, 16, 8, lambda p: _derive_key(p, 16))),
        MenuItem("CAST-128 (CAST5)", lambda: _pycryptodome_block_roundtrip(CAST, 16, 8, lambda p: _derive_key(p, 16))),
        MenuItem("Camellia", lambda: _cryptography_block_roundtrip(camellia, 32, 16)),
        MenuItem("IDEA", lambda: _cryptography_block_roundtrip(idea, 16, 8)),
        MenuItem("SEED", lambda: _cryptography_block_roundtrip(seed, 16, 16)),
        MenuItem("SM4 (Chinese standard)", _sm4_roundtrip),
        MenuItem("GOST 28147-89", _gost_roundtrip),
        MenuItem("AES-GCM", lambda: _aead_demo("AES-GCM")),
        MenuItem("AES-CCM", lambda: _aead_demo("AES-CCM")),
        MenuItem("ChaCha20-Poly1305", lambda: _aead_demo("ChaCha20-Poly1305")),
        MenuItem("Twofish", _unsupported("Twofish", "no maintained package is bundled here")),
        MenuItem("Serpent", _unsupported("Serpent", "no maintained package is bundled here")),
        MenuItem("RC5", _unsupported("RC5", "no maintained package is bundled here")),
        MenuItem("RC6", _unsupported("RC6", "no maintained package is bundled here")),
        MenuItem("Skipjack", _unsupported("Skipjack", "no maintained package is bundled here")),
        MenuItem("PRESENT", _unsupported("PRESENT", "no maintained package is bundled here")),
        MenuItem("SPECK", _unsupported("SPECK", "no maintained package is bundled here")),
        MenuItem("SIMON", _unsupported("SIMON", "no maintained package is bundled here")),
        MenuItem("HC-128 / HC-256", _unsupported("HC-128 / HC-256", "no maintained package is bundled here")),
        MenuItem("Rabbit", _unsupported("Rabbit", "no maintained package is bundled here")),
        MenuItem("Grain", _unsupported("Grain", "no maintained package is bundled here")),
        MenuItem("Trivium", _unsupported("Trivium", "no maintained package is bundled here")),
        MenuItem("MICKEY", _unsupported("MICKEY", "no maintained package is bundled here")),
    ]


def _stream_items() -> list[MenuItem]:
    return [
        MenuItem("RC4 (deprecated/insecure)", lambda: _stream_roundtrip(ARC4, 16, 0)),
        MenuItem("Salsa20", lambda: _stream_roundtrip(Salsa20, 32, 8)),
        MenuItem("ChaCha20", lambda: _stream_roundtrip(ChaCha20, 32, 8)),
        MenuItem("HC-128 / HC-256", _unsupported("HC-128 / HC-256", "no maintained package is bundled here")),
        MenuItem("Rabbit", _unsupported("Rabbit", "no maintained package is bundled here")),
        MenuItem("Grain", _unsupported("Grain", "no maintained package is bundled here")),
        MenuItem("Trivium", _unsupported("Trivium", "no maintained package is bundled here")),
        MenuItem("MICKEY", _unsupported("MICKEY", "no maintained package is bundled here")),
    ]


def _hash_items() -> list[MenuItem]:
    return [
        MenuItem("MD5 (broken)", lambda: _hash_string("MD5", _hash_hashlib("md5"))),
        MenuItem("SHA-1 (broken)", lambda: _hash_string("SHA-1", _hash_hashlib("sha1"))),
        MenuItem("SHA-224", lambda: _hash_string("SHA-224", _hash_hashlib("sha224"))),
        MenuItem("SHA-256", lambda: _hash_string("SHA-256", _hash_hashlib("sha256"))),
        MenuItem("SHA-384", lambda: _hash_string("SHA-384", _hash_hashlib("sha384"))),
        MenuItem("SHA-512", lambda: _hash_string("SHA-512", _hash_hashlib("sha512"))),
        MenuItem("SHA-3 (Keccak) - SHA3-256", lambda: _hash_string("SHA3-256", _hash_hashlib("sha3_256"))),
        MenuItem("RIPEMD-160", lambda: _hash_string("RIPEMD-160", _hash_ripemd160)),
        MenuItem("Whirlpool", _unsupported("Whirlpool", "not exposed by the installed libraries")),
        MenuItem("Tiger", _unsupported("Tiger", "not exposed by the installed libraries")),
        MenuItem("BLAKE2b", lambda: _hash_string("BLAKE2b", _hash_blake2b)),
        MenuItem("BLAKE2s", lambda: _hash_string("BLAKE2s", _hash_blake2s)),
        MenuItem("BLAKE3", lambda: _hash_string("BLAKE3", _hash_b3)),
        MenuItem("GOST R 34.11-2012 (Streebog-256)", lambda: _hash_string("Streebog-256", _hash_streebog("streebog256"))),
        MenuItem("GOST R 34.11-2012 (Streebog-512)", lambda: _hash_string("Streebog-512", _hash_streebog("streebog512"))),
        MenuItem("GOST R 34.11-94", _unsupported("GOST R 34.11-94", "not exposed by the installed libraries")),
        MenuItem("SM3", lambda: _hash_string("SM3", _hash_sm3)),
    ]


def _password_items() -> list[MenuItem]:
    return [
        MenuItem("bcrypt", _password_hash_bcrypt),
        MenuItem("scrypt", _password_hash_scrypt),
        MenuItem("Argon2", _password_hash_argon2),
        MenuItem("PBKDF2", _password_hash_pbkdf2),
    ]


def _mac_items() -> list[MenuItem]:
    return [
        MenuItem("HMAC", _hmac_demo),
        MenuItem("CMAC", _cmac_demo),
        MenuItem("GMAC", _gmac_demo),
        MenuItem("Poly1305", _poly1305_demo),
    ]


def _aead_items() -> list[MenuItem]:
    return [
        MenuItem("AES-GCM", lambda: _aead_demo("AES-GCM")),
        MenuItem("AES-CCM", lambda: _aead_demo("AES-CCM")),
        MenuItem("ChaCha20-Poly1305", lambda: _aead_demo("ChaCha20-Poly1305")),
    ]


def _asymmetric_items() -> list[MenuItem]:
    ml_kem_512 = lambda: _pqc_kem_demo("ml_kem_512", "ML-KEM-512 / CRYSTALS-Kyber")
    ml_dsa_44 = lambda: _pqc_sign_demo("ml_dsa_44", "ML-DSA-44 / CRYSTALS-Dilithium")
    falcon_512 = lambda: _pqc_sign_demo("falcon_512", "Falcon-512")
    sphincs = lambda: _pqc_sign_demo("sphincs_sha2_128f_simple", "SPHINCS+ SHA2-128f")
    return [
        MenuItem("RSA", _rsa_demo),
        MenuItem("Diffie-Hellman (DH)", _dh_demo),
        MenuItem("ElGamal", _unsupported("ElGamal", "textbook encryption support is not exposed reliably here")),
        MenuItem("DSA", _dsa_demo),
        MenuItem("ECDSA", _ecdsa_demo),
        MenuItem("ECDH", _ecdh_demo),
        MenuItem("Ed25519 / Ed448", lambda: _eddsa_menu()),
        MenuItem("ML-KEM (Kyber)", ml_kem_512),
        MenuItem("ML-DSA (Dilithium)", ml_dsa_44),
        MenuItem("Falcon", falcon_512),
        MenuItem("SPHINCS+", sphincs),
        MenuItem("NTRU", _unsupported("NTRU", "not installed in this environment")),
        MenuItem("McEliece", lambda: _pqc_kem_demo("mceliece348864", "Classic McEliece")),
        MenuItem("SIKE", _unsupported("SIKE", "broken and not included")),
    ]


def _eddsa_menu() -> None:
    while True:
        print(Fore.CYAN + f"\n{BANNER_LINE}")
        print(Fore.CYAN + "EdDSA")
        print(Fore.CYAN + BANNER_LINE)
        print(Fore.YELLOW + "1. Ed25519")
        print(Fore.YELLOW + "2. Ed448")
        print(Fore.YELLOW + "0. Back")
        choice = _prompt("Select an option: ")
        if choice == "0":
            return
        if choice == "1":
            _eddsa_demo("Ed25519")
            return
        if choice == "2":
            _eddsa_demo("Ed448")
            return
        _print_error("Invalid option! Try again.")


def main_menu() -> None:
    items = [
        MenuItem("Symmetric Encryption Algorithms", lambda: _menu("Symmetric Encryption", _supported_block_items() + _stream_items())),
        MenuItem("Asymmetric Encryption Algorithms", lambda: _menu("Asymmetric Cryptography", _asymmetric_items())),
        MenuItem("Hashing Algorithms", lambda: _menu("Hashing Algorithms", _hash_items())),
        MenuItem("Password Hashing / KDFs", lambda: _menu("Password Hashing", _password_items())),
        MenuItem("Message Authentication Codes", lambda: _menu("MAC Algorithms", _mac_items())),
        MenuItem("Authenticated Encryption", lambda: _menu("Authenticated Encryption", _aead_items())),
        MenuItem("Classical Ciphers", _classical_cipher_menu),
    ]
    _menu("Crypto Toolkit", items)


def _classical_cipher_menu() -> None:
    items = [
        MenuItem("Substitution Ciphers", lambda: _menu("Substitution Ciphers", _substitution_items())),
        MenuItem("Transposition Ciphers", lambda: _menu("Transposition Ciphers", _transposition_items())),
        MenuItem("Fractionation Ciphers", lambda: _menu("Fractionation Ciphers", _fractionation_items())),
        MenuItem("Product / Combination Ciphers", lambda: _menu("Product Ciphers", _product_items())),
        MenuItem("Mechanical / Machine Ciphers", lambda: _menu("Mechanical Ciphers", _mechanical_items())),
        MenuItem("Other Classical Methods", lambda: _menu("Other Classical Methods", _other_classical_items())),
    ]
    _menu("Classical Ciphers", items)


def run() -> None:
    main_menu()


if __name__ == "__main__":
    run()
