# LockNCrypt - Secure File Encryption with 2FA 🔒
Python 3.8+
Security AES-256-CBC

## Project Info

<div align="center">

| **Version** | **License** | **Python** | **Security** |
|------------|------------|------------|-------------|
| ![Version](https://img.shields.io/badge/Version-1.0-blue) | ![License](https://img.shields.io/badge/License-MIT-green) | ![Python](https://img.shields.io/badge/Python-3.8+-red) | ![Security](https://img.shields.io/badge/Security-AES--256--CBC-orange) |

</div>

A Python-based secure file encryption system with Two-Factor Authentication (2FA) using Google Authenticator (TOTP) and SMS OTP verification via Telesign API.

# Features ✨
## Dual-Factor Authentication
- Time-based OTP (Google/Microsoft Authenticator)
- SMS OTP verification (via Telesign API)

## Military-Grade Encryption
- AES-256 CBC mode encryptioN
- Multiple encryption iterations for enhanced security

## User-Friendly GUI
- Built with Tkinter for easy file selection
- Progress bars and real-time feedback

## Security Hardened
- Environment variable configuration
- Input validation and attempt limiting
- Automatic cleanup of temporary files

# Installation ⚙️
## Prerequisites
- Python 3.8+
- Telesign API account (for SMS OTP) - Make sure to add your phone number in it.

# Setup
- git clone https://github.com/krishp4204/LockNCrypt.git
- cd ValtAuth-Secure


# Install dependencies:
- pip install -r requirements.txt

# Usage 🚀
Run the application for the first time:
python3 lockncrypt.py
- It will ask you to enter telesign's API key. Customer ID and your phone number.
- After that, the script will create a QR code for the Google/Microsoft authenticator.

# Workflow
## Authentication 🔐
- Scan the generated QR code with Google Authenticator
- Enter the 6-digit TOTP code
- Verify SMS OTP sent to your phone

## File Operations 📂
- Choose between encryption/decryption
- Select your file
- Optionally apply multiple encryption rounds

## Output 🩻
- Encrypted files get .enc extension
- Decrypted files restore original format


