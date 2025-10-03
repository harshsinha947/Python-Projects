Here is the complete content for your Password Security Suite, formatted in standard Markdown.

🔐 Password Security Suite (Python CLI)
This is a local-only Command Line Interface (CLI) application built in Python that functions as both a secure password manager and a real-time password strength checker.

The application enforces security by using a single Master Password to encrypt all stored credentials, ensuring the passwords are never stored in plain text.

✨ Features
Enforced Authentication: Access is strictly controlled by a Master Password. The vault cannot be accessed or decrypted without it.

Secure Storage: Uses the industry-standard Fernet (AES 128-bit CBC) symmetric encryption from the cryptography library to protect passwords.

Password Strength Checker: Analyzes passwords in real-time, providing a score and specific feedback on how to improve weak passwords.

Password Generator: Creates highly strong, random passwords that meet 'Excellent' security criteria.

Vault Management: Allows the user to add, retrieve, and view a list of all saved entries (site/username pairs).

💻 Setup and Installation
Prerequisites
You must have Python 3 installed on your system.

Installation Steps
Clone or Download: Get the password_suite.py file and place it in a dedicated project folder.

Install Dependencies: The project requires the powerful cryptography library. Open your terminal in the project folder and run the following command:

Bash

pip install cryptography
(Note: getpass is a built-in Python module and does not need to be installed separately.)

🚀 How to Run the Application
Navigate to the project directory in your terminal (PowerShell, Command Prompt, or Bash) and run the script:

Bash

python password_suite.py
First-Time Run (Setup)
The program will automatically detect the absence of the security key and prompt you:

Set your Master Password (Min 12 Chars): Choose a unique, very strong password you have never used before. DO NOT FORGET THIS PASSWORD, as it is the only key to your vault.

Subsequent Runs (Login)
The program will prompt you to enter the existing Master Password:

Enter Master Password: You have 3 attempts to enter the correct password. If all attempts fail, the program will terminate, denying access to the encrypted data.

📝 Menu Options
Once authenticated, the main menu provides the following options:

Option	Functionality	Security Note
1	Add New Password/Entry	Checks password strength before saving (saves encrypted).
2	Retrieve Specific Password	Prompts for a website name and displays the decrypted password.
3	View All Saved Entries	Lists all site names and usernames in the vault (passwords are hidden).
4	Generate Strong Password	Creates and displays a highly secure, random 16-character password.
5	Check Custom Password Strength	Analyzes any password entered against the security criteria.
6	Exit	Saves the current state of the vault and closes the application.
