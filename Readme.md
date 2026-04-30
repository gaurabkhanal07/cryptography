# Cryptography Tool in Python

A command-line cryptography playground with menus for symmetric encryption, asymmetric crypto, hashing, password hashing, MACs, and authenticated encryption. The toolkit uses standard Python crypto libraries plus optional third-party packages to cover as many of the requested algorithms as possible.

---

## Features

- Symmetric encryption demos for common block and stream ciphers
- Asymmetric demos for RSA, DH, DSA, ECDSA, ECDH, and EdDSA
- Hashing, password hashing, MAC, and AEAD helpers
- Post-quantum KEM and signature demos via `pqcrypto`
- Clear labels for algorithms that are deprecated or unavailable in this build

---

## Prerequisites

- Python 3.x
- Pip package manager

---

## Installation

1. Clone the repository

```bash
git clone https://github.com/gaurabkhanal07/cryptography.git
cd cryptography
```

2. Create a virtual environment

```bash
python -m venv .venv
```

3. Activate it in Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the script, run:

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
```

4. Install the requirements

```bash
pip install -r requirements.txt
```

5. Start the toolkit

```bash
python main.py
```

---

## Notes

- Some entries in the menus are intentionally marked as unavailable because the corresponding algorithms are not exposed by the installed Python crypto packages.
- Deprecated algorithms such as MD5, SHA-1, and RC4 are included for learning purposes only.
