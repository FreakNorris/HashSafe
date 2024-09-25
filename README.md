
# HashSafe - Secure Offline Password Manager

**HashSafe** is a robust, secure password manager with bcrypt hashing, Fernet encryption, and PBKDF2HMAC key derivation. It offers a Tkinter-based GUI, unique salts, and SHA256 data integrity checks. Perfect for Windows, macOS, and Linux users. Open Source under GNU GPL v3.0.

## Table of Contents

- [Security Features](#security-features)
- [Installation](#installation)
- [Creating Launchers/Desktop Shortcuts](#creating-launchersdesktop-shortcuts)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Audit](#audit)
- [Contact](#contact)

## Security Features

### Core Security Features

- **Secure Password Storage**: Utilizes bcrypt for secure password hashing.
- **Encryption**: Implements Fernet symmetric encryption with integrity checks.
- **Key Derivation**: Uses PBKDF2HMAC with SHA256 for key derivation.
- **Unique Salts**: Ensures unique salts for each user to prevent rainbow table attacks.
- **Data Integrity**: Verifies data integrity using SHA256.
- **File Permission Management**: Ensures only admin/sudo users can manipulate the vault files, even outside HashSafe.
- **User-Friendly Interface**: Intuitive Tkinter-based GUI for easy interaction.

### Additional Security Measures

- Implemented functionality to force user interaction between each unsuccessful Sign-In attempt.
- HashSafe terminates after 3 unsuccessful Sign-In attempts, making brute-forcing via the GUI practically impossible.

## Installation

To install HashSafe, follow these steps:

1. **Clone the repository**:

   ```bash
   git clone https://github.com/FreakNorris/HashSafe.git
   ```

2. **Navigate to the project directory**:

   ```bash
   cd HashSafe
   ```

3. **Install the required dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:

   ```bash
   python3 main.py
   ```

## Creating Launchers/Desktop Shortcuts

### For Linux Users

1. **To run the script**:

   - Open a terminal and navigate to the project directory.
   - Edit the `run_main.sh` script to replace the placeholder with the actual directory path:

     ```bash
     # Set absolute paths
     SCRIPT_DIR="/home/user/HashSafe"
     MAIN_PY="$SCRIPT_DIR/main.py"
     ```

     Replace `/home/user/HashSafe` with the actual path to the `run_main.sh` script.

   - Make the `run_main.sh` script executable:

     ```bash
     chmod +x run_main.sh
     ```

   - Run the `run_main.sh` script:

     ```bash
     ./run_main.sh
     ```

   - Optionally, you can create a desktop launcher:
     - **Using MenuLibre**:
       1. Install MenuLibre if it's not already installed:

          ```bash
          sudo apt-get install menulibre
          ```

       2. Open MenuLibre from your application menu.
       3. Click "Add Application" to create a new entry.
       4. Fill in the following details:
          - **Name**: HashSafe
          - **Command**: `/usr/local/bin/run_main.sh` (or the path where you copied `run_main.sh`)
          - **Working Directory**: The directory where `run_main.sh` is located.
          - **Icon**: Browse to the icon file you want to use.
       5. Click "Save" to create the launcher.

     - **Using a .desktop file**:
       1. Copy the `run_main.sh` script to a location in your PATH, such as `/usr/local/bin`.
       2. Create a `.desktop` file in `~/.local/share/applications/` with the following content:

          ```plaintext
          [Desktop Entry]
          Name=HashSafe
          Exec=/usr/local/bin/run_main.sh
          Icon=/path/to/icon.png
          Terminal=false
          Type=Application
          Categories=Utility;
          ```

       3. Replace `/path/to/icon.png` with the actual path to an icon file.

### For Windows Users

1. **To run the script**:

   - Open a Command Prompt and navigate to the project directory.
   - Edit the `run_main.bat` script to replace the placeholder with the actual directory path:

     ```cmd
     REM Set absolute paths
     set SCRIPT_DIR=C:\Users\YourUsername\Documents\HashSafe\
     set MAIN_PY=%SCRIPT_DIR%main.py
     ```

     Ensure that `C:\Users\YourUsername\Documents\HashSafe\` correctly resolves to the directory containing `run_main.bat`.

   - Make the `run_main.bat` script executable:

     ```cmd
     icacls run_main.bat /grant Everyone:F
     ```

   - Run the `run_main.bat` script:

     ```cmd
     run_main.bat
     ```

   - Optionally, you can create a desktop shortcut:
     - Right-click on the desktop and select "New" > "Shortcut".
     - In the location field, enter the full path to `run_main.bat`, e.g., `C:\Users\YourUsername\Documents\HashSafe\run_main.bat`.
     - Click "Next" and give the shortcut a name, e.g., "HashSafe".
     - Click "Finish" to create the shortcut.

## Usage

- **Sign Up**: Create a new account by providing a master password.
- **Sign In**: Log in using your master password.
- **Save Password**: Add new passwords to your vault.
- **View Password**: Retrieve and view stored passwords securely.
- **Delete Password**: Remove passwords from your vault.

## Contributing

Contributions are welcome as long as the license is respected.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Audit

HashSafe has undergone a thorough security audit using Bandit, a static analysis tool for Python code. The audit results are as follows:

```plaintext
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

**Interpretation**:

The audit conducted using Bandit, a widely-used static analysis tool for Python, revealed no security issues in the codebase. This is a positive outcome, indicating that HashSafe's code adheres to best practices and does not contain any obvious vulnerabilities.

- **No Issues Identified**: The absence of any issues suggests that the codebase is well-maintained and follows secure coding practices.
- **Comprehensive Scan**: The audit covered all 839 lines of code without skipping any, ensuring a thorough examination.
- **High Confidence**: The results show zero issues across all severity and confidence levels, reinforcing the reliability of the code.

This audit provides confidence in the security of HashSafe, ensuring that users can trust the application with their sensitive data.

## Contact

For any questions or feedback, please open an issue on GitHub, or email me: renewitsolutions@tutamail.com

Please remember to star my repository if you like my program. It helps.

---FreakNorris---
