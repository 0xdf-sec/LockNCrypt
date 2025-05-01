# LockNCrypt - Secure File Encryption with 2FA 🔒
![LOCKnCRYPT](https://github.com/user-attachments/assets/8796c8c8-6a26-4865-ace5-76855782d3ce)

# ⚠️ Note: This script is currently fully supported only on Windows. Linux/macOS compatibility for environment variable persistence is under development.

### Project Info

- ![Version](https://img.shields.io/badge/Version-1.0-blue)  
- ![License](https://img.shields.io/badge/License-MIT-green)  
- ![Python](https://img.shields.io/badge/Python-3.8+-red)  
- ![Security](https://img.shields.io/badge/Security-AES--256--CBC-orange)

A Python-based secure file encryption system with Two-Factor Authentication (2FA) using Google Authenticator (TOTP) and SMS OTP verification via Telesign API.

# Features ✨
### Dual-Factor Authentication
- Time-based OTP (Google/Microsoft Authenticator)
- SMS OTP verification (via Telesign API)

### Military-Grade Encryption
- AES-256 CBC mode encryptioN
- Multiple encryption iterations for enhanced security

### User-Friendly GUI
- Built with Tkinter for easy file selection
- Progress bars and real-time feedback

### Security Hardened
- Environment variable configuration
- Input validation and attempt limiting
- Automatic cleanup of temporary files



# Installation ⚙️
## Prerequisites
```bash
1. Install Python 3.8+  
python --version  # Verify installation  

2. Sign up for Telesign (Free $5 credit = 500 OTPs)  
https://portal.telesign.com/signup  
```

### Setup for Windows
```bash
Clone this repository from GitHub Desktop
Install the requiremnets
And RUN
```

### Setup for Linux
```bash
git clone https://github.com/0xdf-sec/LockNCrypt.git
cd LockNCrypt
```

### Install dependencies:
```bash
pip3 install -r requirements.txt
```
### Usage 🚀
```bash
Run the application for the first time:
python3 lockncrypt.py
- It will ask you to enter telesign's API key. Customer ID and your phone number.
- After that, the script will create a QR code for the Google/Microsoft authenticator.
```


# Workflow 🔀
### Authentication 🔐
- Scan the generated QR code with Google Authenticator
- Enter the 6-digit TOTP code
- Verify SMS OTP sent to your phone

### File Operations 📂
- Choose between encryption/decryption
- Select your file
- Optionally apply multiple encryption rounds

### Output 🩻
- Encrypted files get .enc extension
- Decrypted files restore original format


