PASSWD - Password Manager

passwd 2.0:

Updated version of paswd.

Realized that , some sort of backup along with availability of the passwords online and access with any device was necessary, hence i have modified the code and uploded it to replit , so now i can access my passwords from any device online. However , the stored passwords(encrypted) is still available on the cloud so it can be a potential vulnerability.

Overview:
PASSWD is a OFFLINE command-line password manager that provides functionalities for generating strong passwords, adding passwords to a secure vault, deleting passwords from the vault, and viewing stored passwords.

Features:

1.Generate Strong Passwords:
The program allows you to generate strong and secure passwords with customizable length.
Add Password to Vault:

2.Store your passwords securely in the vault by providing the website URL, login or user ID, and the password in plain text.
Delete Password from Vault:

3.Remove a stored password from the vault by entering the website URL and login/user ID associated with the password.
View Passwords in Vault:

4.View all stored passwords in the vault, displaying the website URL, login/user ID, and the decrypted password.

Prerequisites:
1.Python 3.x
2.Notepad


Detailed Overview of Functions:

1. generate()
This function is responsible for generating a strong and secure password. It prompts the user to input the desired length for the password and ensures that the length is at least 6 characters for security. The function then creates a password by combining lowercase letters, uppercase letters, digits, and punctuation characters. The final password is shuffled to enhance randomness.

2. SetVaultKey()
This function sets the master password for accessing the password vault. It prompts the user to enter a new master password and uses SHA-3-256 hashing to securely store the hashed version of the password in a file. This master password is later used to open the vault and access stored passwords.

3. OpenVault()
The OpenVault() function is responsible for opening the password vault. It prompts the user to enter the vault password and uses SHA-3-256 hashing to compare the entered password with the stored hashed master password. If the passwords match, the vault is considered open; otherwise, the user is prompted to re-enter the password until a correct one is provided.

4. encrypt_string(text, key="MASTER_PASSWORD")
This function takes a text (password) and encrypts it using a bitwise XOR operation with a given key. The result is then base64-encoded for better representation. This encryption is used before storing passwords in the vault to enhance security.

5. decrypt_string(encrypted_text, key="MASTER_PASSWORD")
The decrypt_string() function performs the reverse operation of encrypt_string(). It takes an encrypted text, decodes it from base64, and decrypts it using a bitwise XOR operation with a given key. This decryption is used when displaying stored passwords.

6. Storage(x)
The Storage() function is a higher-level function that handles the addition, deletion, and viewing of passwords in the vault. It takes an argument x to determine the specific operation to be performed (1 for adding, 2 for deleting, and 3 for viewing).

- View()
This nested function reads the contents of the vault file and displays the stored passwords. It decrypts each password using the decrypt_string() function before presenting it to the user.

- Add(url, username, new_password)
This nested function adds a new password entry to the vault. It prompts the user for the website URL, login or user ID, and the password in plain text. The password is then encrypted using the encrypt_string() function before being appended to the vault file.

- delete_line(username, login_id)
This nested function allows the user to delete a specific password entry from the vault. It reads the contents of the vault file, skips the line to be deleted, and rewrites the remaining lines.


Security Note:
Ensure you have a strong master key when setting up the vault for enhanced security.
Encryption Strength of the passwords depends the complexity of the Master key.
