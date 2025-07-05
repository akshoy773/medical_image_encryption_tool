# medical_image_encryption_tool
A secure image encryption tool for protecting medical and sensitive images using a hybrid cryptosystem:

 DNA-based cryptography

 Chaotic maps (PWLCM + Logistic)

 PBKDF2 key expansion

 HMAC for file integrity

This project provides strong encryption for color and grayscale images, ensuring confidentiality, integrity, and resistance against statistical and differential attacks.

 Features
 Hybrid Encryption System

DNA Encoding/Decoding with 8 dynamic rules

Hybrid Chaotic Maps (PWLCM + Logistic) for generating secure sequences

Multi-round permutation and diffusion for robust encryption

Pixel Position Permutation (Spatial Shuffle)

Full File HMAC for integrity verification (detects tampering/corruption)

 PBKDF2 Key Derivation

Strengthens user password with salt and 200,000 iterations.

 Supports Color & Grayscale Images

Works with PNG, JPEG, BMP, etc.

 GUI Built with Tkinter

Simple interface to select, encrypt, decrypt, and save images.

 No External Dependencies for Metadata

HMAC and salt are embedded directly in the PNG metadata.

Installation
 Prerequisites
Python 3.8+
pip
 Install Required Libraries
pip install pillow numpy

python image_encryption_tool.py
 GUI Steps
Enter Key – Input a strong password.

Select Image – Choose the image to encrypt/decrypt.

Encrypt Image – Encrypts and displays the encrypted image.

Decrypt Image – Decrypts using the same password.

Save Processed Image – Saves with embedded HMAC and salt.

 Encryption Process
Key Expansion

PBKDF2 (SHA-256, Salted, 200k iterations).

Hybrid Chaotic Map Sequence Generation

Piecewise Linear Chaotic Map (PWLCM) and Logistic Map.

Pixel Position Permutation

DNA Encoding with Dynamic Rules

Permutation and Chaotic XOR Diffusion

HMAC Generation

SHA-256 based on processed image bytes.

 File Metadata
Encrypted PNG files store:

 hmac: SHA-256 HMAC of image data

 salt: PBKDF2 salt in hex

This enables authentication during decryption.
