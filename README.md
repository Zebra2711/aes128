# AES with a GUI in Python
Advanced Encryption Standard includes:
- Block Chaining ([CBC](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf#page=17))
- Electronic Codebook ([ECB](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf#page=16))
- Secure password hashing algorithm [Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- Cryptographic Message Syntax [PKCS#7](https://datatracker.ietf.org/doc/html/rfc2315))
- Hash-based message authentication codes ([HMAC](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf)) SHA256
  
## Preview

![2024-12-23_23-14](https://github.com/user-attachments/assets/4c377459-d82e-4e05-a0b6-4b12167d88be)

## Usage
Requires python 3.8 or higher.
```
git clone https://github.com/Zebra2711/aes-python.git
cd aes-python
python3 -m venv .venv
.venv/bin/pip install pyperclip customtkinter pyargon2
.venv/bin/python aes.py
```
## References
[AES-Python](https://github.com/bozhu/AES-Python) of [@bozhu](https://github.com/bozhu)
