# Password Practice Utility

A secure command-line tool for practicing password recall without ever storing your actual password on disk. Perfect for reinforcing muscle memory of complex passwords or testing your ability to remember important credentials.

## How It Works

This utility uses a clever approach to password practice:

1. **Setup**: You enter your password once, and the tool creates an encrypted "success token" file
2. **Practice**: During practice sessions, you type your password and the tool attempts to decrypt the token
3. **Verification**: If decryption succeeds and reveals the success message, your password was correct
4. **Security**: Your actual password is never written to disk - only an encrypted verification token

## Features

- ✅ **Zero password storage** - Your password never touches the disk
- 🔐 **Strong encryption** - Uses AES-GCM with Scrypt key derivation
- 🧠 **Memory protection** - Optional memory locking to prevent swapping
- 📁 **Portable tokens** - Small, shareable encrypted files
- 🎯 **Simple interface** - Easy command-line operation

## Installation

### Prerequisites

- Python 3.6 or higher
- pip package manager

### Install Dependencies

```bash
pip install cryptography
```

### Download the Script

```bash
# Clone the repository
git clone https://github.com/ancientastronauttheorist/password-practice-utility.git
cd password-practice-utility

# Or download directly
wget https://raw.githubusercontent.com/ancientastronauttheorist/password-practice-utility/main/password_practice.py
chmod +x password_practice.py
```

## Usage

### 1. Create a Practice Token

First, create an encrypted token file with your password:

```bash
python3 password_practice.py init my_token.txt
```

You'll be prompted to:
- Enter your password
- Confirm your password

The tool creates a small encrypted file (`my_token.txt`) containing only an encrypted "success!" message.

### 2. Practice Your Password

Use the token file to practice recalling your password:

```bash
python3 password_practice.py practice my_token.txt
```

- Type your password when prompted
- Get instant feedback: ✅ for correct, ❌ for incorrect
- Type `q` to quit the practice session

### Advanced Options

#### Memory Locking (Linux/macOS)

For enhanced security, use the `--mlock` flag to attempt locking the process memory:

```bash
# During token creation
python3 password_practice.py init my_token.txt --mlock

# During practice
python3 password_practice.py practice my_token.txt --mlock
```

**Note**: Memory locking may require elevated privileges and is not available on Windows.

## Example Session

```bash
$ python3 password_practice.py init work_password.txt
Create practice password: [hidden input]
Repeat password: [hidden input]
Created token at work_password.txt. Keep this file safe.

$ python3 password_practice.py practice work_password.txt
Password practice. Type your password (or 'q' to quit).
> [wrong password]
❌ Incorrect.
> [correct password]
✅ Correct!
> q
Bye.
```

## Security Features

### Encryption Details
- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: Scrypt with strong parameters (N=16384, r=8, p=1)
- **Salt**: 16 random bytes per token
- **Nonce**: 12 random bytes (standard for AES-GCM)

### Memory Protection
- Sensitive data stored in `bytearray` objects that are wiped after use
- Optional memory locking to prevent sensitive data from being swapped to disk
- Password strings cleared from memory as soon as possible

### No Password Storage
- Your actual password is never written to any file
- Only an encrypted verification token is stored
- Token files are safe to share or backup (they don't reveal your password)

## Use Cases

- **Password Training**: Practice typing complex work passwords
- **Security Drills**: Test your ability to recall backup/recovery passwords
- **Team Training**: Share tokens (not passwords) for training exercises
- **Memory Reinforcement**: Build muscle memory for important credentials
- **Travel Security**: Practice passwords before trips when you might be stressed

## File Format

Token files are JSON with base64-encoded binary data:

```json
{
  "magic": "pwpractice-v1",
  "salt_b64": "...",
  "nonce_b64": "...",
  "kdf": "scrypt",
  "params": {
    "n": 16384,
    "r": 8,
    "p": 1,
    "key_len": 32
  },
  "ciphertext_b64": "..."
}
```

## Contributing

Contributions welcome! Please feel free to submit pull requests or open issues for:

- Additional KDF algorithms
- Platform-specific security enhancements
- UI improvements
- Documentation updates

## Security Considerations

- **Token files are safe to backup** - they don't contain your password
- **Use strong, unique passwords** - this tool helps you practice them
- **Keep token files secure** - while they don't contain passwords, they're still sensitive
- **Memory locking requires privileges** - may need `sudo` on some systems

## License

The Unlicense - see LICENSE file for details.

## Disclaimer

This tool is provided as-is for educational and productivity purposes. While it implements strong cryptographic practices, no security tool is perfect. Use at your own risk and always follow your organization's security policies.
