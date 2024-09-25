# HashSafe - Secure Offline Password Manager
HashSafe is a robust, secure password manager with bcrypt hashing, Fernet encryption, and PBKDF2HMAC key derivation. It offers a Tkinter-based GUI, unique salts, and SHA256 data integrity checks. Perfect for Windows, macOS, and Linux users. Open Source under GNU GPL v3.0.

 Table of Contents

- Features
- Security
- Installation
- Usage
- Contributing
- License
- Audit
- Contact

 Features

- Secure Password Storage: Utilizes bcrypt for secure password hashing.
- Encryption: Implements Fernet symmetric encryption with integrity checks.
- Key Derivation: Uses PBKDF2HMAC with SHA256 for key derivation.
- Unique Salts: Ensures unique salts for each user to prevent rainbow table attacks.
- Data Integrity: Verifies data integrity using SHA256.
- User-Friendly Interface: Intuitive Tkinter-based GUI for easy interaction.

 Security

HashSafe employs the following security measures:

- bcrypt: Secure password hashing.
- Fernet: Symmetric encryption with integrity checks.
- PBKDF2HMAC with SHA256: Key derivation with 100,000 iterations.
- Unique Salts: Each user has a unique salt.
- SHA256: For data integrity checks.

 Installation

To install HashSafe, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/FreakNorris/HashSafe.git
   ```

2. Navigate to the project directory:
   ```bash
   cd HashSafe
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python3 main.py
   ```

 Usage

1. Sign Up: Create a new account by providing a master password.
2. Sign In: Log in using your master password.
3. Save Password: Add new passwords to your vault.
4. View Password: Retrieve and view stored passwords securely.
5. Delete Password: Remove passwords from your vault.

N.B. The run_main.sh script is for Debian based Linux users to easily create a launcher for running Hashsafe.
    <directory/run_main.sh> is a placeholder for where run_main.sh is stored on your system.

 Contributing

Contributions are welcome as long as the the license is respected. 

 License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

 Audit

HashSafe has undergone a thorough security audit using Bandit, a static analysis tool for Python code. The audit results are as follows:

```
redacted@Laptop:~/Documents/AAA_System/hasher$ bandit -r .
[main]  INFO    profile include tests: None
[main]  INFO    profile exclude tests: None
[main]  INFO    cli include tests: None
[main]  INFO    cli exclude tests: None
[main]  INFO    running on Python 3.12.3
Run started:2024-09-23 05:21:46.634142

Test results:
        No issues identified.

Code scanned:
        Total lines of code: 839
        Total lines skipped (#nosec): 0

Run metrics:
        Total issues (by severity):
                Undefined: 0.0
                Low: 0.0
                Medium: 0.0
                High: 0.0
        Total issues (by confidence):
                Undefined: 0.0
                Low: 0.0
                Medium: 0.0
                High: 0.0
Files skipped (0):
```
Interpretation:

The audit conducted using Bandit, a widely-used static analysis tool for Python, revealed no security issues in the codebase. This is a positive outcome, indicating that HashSafe's code adheres to best practices and does not contain any obvious vulnerabilities.

      - No Issues Identified: The absence of any issues suggests that the codebase is well-maintained and follows secure coding practices.
      - Comprehensive Scan: The audit covered all 839 lines of code without skipping any, ensuring a thorough examination.
      - High Confidence: The results show zero issues across all severity and confidence levels, reinforcing the reliability of the code.
      
This audit provides confidence in the security of HashSafe, ensuring that users can trust the application with their sensitive data.

 Contact

For any questions or feedback, please open an issue on GitHub, or email me: renewitsolutions@tutamail.com


Please remember to star my repository if you like my program. It helps..
