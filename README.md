# Secure Medical Prescription Transmission System

A cryptographically secure system for creating, transmitting, and verifying medical prescriptions digitally. This project demonstrates key cybersecurity concepts including end-to-end encryption, digital signatures, tamper detection, and public key infrastructure.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Command Line Interface](#command-line-interface)
  - [Streamlit Web Interface](#streamlit-web-interface)
- [Security Features](#security-features)
- [Demo Modes](#demo-modes)
- [Technical Details](#technical-details)
- [Future Enhancements](#future-enhancements)
- [Disclaimer](#disclaimer)

## Overview

The Secure Medical Prescription Transmission System enables healthcare providers to create legitimate, verifiable electronic prescriptions that can only be read by the intended pharmacy. The system protects patient privacy and prevents tampering or forgery of prescriptions using modern cryptographic techniques.

## Features

- 🔒 **End-to-end encryption** of prescription data
- 🔑 **Public key infrastructure** for secure key exchange
- 🔏 **Digital signatures** to verify prescription authenticity
- 🛡️ **Tamper detection** to prevent unauthorized modifications
- 📝 **Command line and web interfaces** for demonstration
- 🧪 **Simulation modes** to demonstrate security features

## System Architecture

The system consists of two main components:

1. **Core Backend Module** (`secure_prescription_system.py`) - A Python library that implements the core cryptographic functionality
2. **Streamlit Web Interface** (`secure_prescription_streamlit.py`) - A user-friendly web application to demonstrate the system

### Core Components:

- `User` - Represents doctors and pharmacies with cryptographic key pairs
- `Prescription` - Contains prescription information with unique IDs
- `DoctorPortal` - Creates, encrypts, and signs prescriptions
- `PharmacyPortal` - Decrypts, verifies, and processes prescriptions

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-prescription-system.git
   cd secure-prescription-system
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install pycryptodome streamlit
   ```

## Usage

The system can be used through either a command-line interface or a web interface.

### Command Line Interface

Run the command line version with:

```bash
python secure_prescription_system.py
```

The CLI offers these options:
1. Run a complete demonstration
2. Run a tampering detection demonstration
3. Create a custom prescription
4. Exit

### Streamlit Web Interface

Launch the web interface with:

```bash
streamlit run secure_prescription_streamlit.py
```

The web interface provides these sections:
- **Home** - Overview and introduction to the system
- **Doctor Portal** - Create and encrypt prescriptions
- **Pharmacy Portal** - Decrypt and verify prescriptions
- **Run Demo** - Automated demonstration of the complete workflow
- **Tamper Detection** - Demonstration of security features

## Security Features

### Encryption

The system uses a hybrid encryption approach:
- **Symmetric encryption (AES-CBC)** for the prescription data
- **Asymmetric encryption (RSA-2048)** for key exchange and digital signatures

### Digital Signatures

Each prescription is digitally signed by the doctor's private key to:
- Verify the authenticity of the prescription
- Ensure the prescription hasn't been tampered with
- Provide non-repudiation (proof of prescription origin)

### Unique Prescription IDs

Each prescription receives a unique identifier generated from:
- Doctor's name
- Patient details
- Timestamp
- SHA-256 hashing algorithm

## Demo Modes

### Complete Workflow Demonstration

Demonstrates the entire process:
1. Key exchange between doctor and pharmacy
2. Prescription creation by the doctor
3. Encryption and signing of the prescription
4. Secure transmission of the prescription
5. Decryption and verification by the pharmacy

### Tamper Detection Demonstration

Shows how the security features detect tampering:
1. A legitimate prescription is created
2. The prescription is tampered with (modified)
3. The pharmacy tries to verify the tampered prescription
4. The system detects the tampering and rejects the prescription

## Technical Details

### Cryptographic Algorithms

- **RSA-2048** for asymmetric encryption and digital signatures
- **AES-128-CBC** for symmetric encryption of prescription data
- **SHA-256** for hashing and prescription ID generation

### Data Flow

1. Doctor creates prescription with patient information
2. System encrypts prescription with a random AES key
3. AES key is encrypted with pharmacy's public RSA key
4. Prescription is digitally signed with doctor's private RSA key
5. Secure package containing encrypted data, encrypted key, and signature is transmitted
6. Pharmacy decrypts AES key using private RSA key
7. Pharmacy decrypts prescription data using AES key
8. Pharmacy verifies signature using doctor's public RSA key

## Future Enhancements

Potential improvements for a production system:

- User authentication with multi-factor authentication
- Integration with electronic health record (EHR) systems
- Certificate authority for key distribution and validation
- Blockchain-based prescription ledger for auditability
- QR code generation for paper-based backup
- Mobile application for patients and healthcare providers
- Automated pharmacy dispensing integration

## Disclaimer

This system is developed for educational and demonstration purposes only. While it implements robust cryptographic security features, a production medical system would require additional security measures, compliance with healthcare regulations (HIPAA, GDPR, etc.), and thorough security auditing.

---

© 2025 Your Organization | Licensed under MIT
