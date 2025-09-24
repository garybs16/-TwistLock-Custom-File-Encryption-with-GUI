# 🔒 TwistLock – Custom File Encryption with GUI

TwistLock is an **educational file encryption program** built in Python.  
It features a **custom reversible cipher**, **passphrase-based keying**, and both a **CLI** and **Tkinter GUI** interface for encrypting and decrypting files.  

⚠️ **Note**: TwistLock is not an industry-grade cipher. It was designed for learning purposes and should not be used to protect sensitive information.

---

## ✨ Features

- **Custom encryption algorithm**  
  - Multi-step reversible transform:  
    - Position permutation  
    - Byte rotations  
    - XOR keystream  
    - Half-block swap  
    - Substitution (S-box)  
  - Passphrase + random salt → SHAKE-256 KDF → unique key material
- **File I/O**
  - Encrypts/decrypts arbitrary text or binary files
  - Chunked file processing (64 KB per chunk)
  - Simple file header (tag + salt)
  - Error handling for missing files, permission errors, or identical input/output paths
- **Cross-platform interfaces**
  - **CLI mode** – text-based menu for fast usage
  - **GUI mode** – Tkinter-based graphical interface with file pickers, status messages, and passphrase entry
- **Bonus functionality**
  - Key-based encryption (user supplies passphrase)
  - GUI file selector for extra usability

---

## 🚀 Getting Started

### Requirements
- Python **3.6+**
- Tkinter (ships with most Python distributions)

### Installation
Clone this repository:
```bash
git clone https://github.com/YOUR-USERNAME/twistlock.git
cd twistlock
