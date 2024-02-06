# OFFLINE password manager
# Requires Notepad Feature


'''
1.Generate a strong password 
2.Add password to vault
3.Delete password from vault
4.View password from vault
'''

import hashlib
import os
import random
import string
import base64
global file_path

file_path="#the txt file path here to store passwords"


def generate():
    length=int(input("Enter the length of password you want: "))

    if length <= 5:
        print("Password length must be at least 6 characters for a secure password")
    password = (
        random.choice(string.ascii_lowercase) +
        random.choice(string.ascii_uppercase) +
        random.choice(string.digits) +
        random.choice(string.punctuation)
    )

    
    for _ in range(length - 4):
        password += random.choice(string.punctuation
 + string.ascii_lowercase + string.digits + string.ascii_uppercase)

    password_list = list(password)
    random.shuffle(password_list)
    Generated_Password = ''.join(password_list)
    print("Generated password: ",Generated_Password)




def SetVaultKey():
    
    input_string = input("Enter New Master password: ")

    hash_object = hashlib.sha3_256()


    for i in range(0,15):
        hash_object.update(input_string.encode('utf-8'))
        hashed_string = hash_object.hexdigest()
    with open(file_path,"w") as file:
        file.write(hashed_string)




global master_pass
def OpenVault():
    
    master_pass=input("Enter Vault password: ")
    hash_obj=hashlib.sha3_256()
    for i in range(0,15):
        hash_obj.update(master_pass.encode('utf-8'))
        new_hash=hash_obj.hexdigest()
    
    with open(file_path,"r") as file:
        file.seek(0)
        stored_hash=file.read(64)
        if stored_hash==new_hash:
            print("VAULT IS OPEN")
            
        else:
            print("Wrong password")
            OpenVault()
            
    return master_pass        


global key






def encrypt_string(text, key="default_value"):
    encrypted = ''.join(chr(ord(char) ^ ord(key[i % len(key)])) for i, char in enumerate(text))
    encrypted_base64 = base64.b64encode(encrypted.encode()).decode()
    return encrypted_base64


import base64

def decrypt_string(encrypted_text, key="default_value"):
    encrypted_bytes = base64.b64decode(encrypted_text.encode())
    decrypted = ''.join(chr(encrypted_bytes[i] ^ ord(key[i % len(key)])) for i in range(len(encrypted_bytes)))
    return decrypted




def Storage(x):
                
    
    
    
    def View():
        try:
            with open(file_path, 'r') as file:
            # Read all lines from the file
                lines = file.readlines()

            # Check if there are at least two lines in the file
                if len(lines) >= 2:
                # Display content starting from the second line
                    for line in lines[1:]:
                        line = line.strip()
                        storing_before_colon = []
                        storing_after_colon = False
                        stored_after_colon = []

                        for char in line:
                            if char == ':':
                                storing_after_colon = True
                            elif storing_after_colon:
                                stored_after_colon.append(char)
                            else:
                                storing_before_colon.append(char)

                        before_colon = ''.join(storing_before_colon)
                        after_colon = ''.join(stored_after_colon)
                        global decryted_password
                        decryted_password=decrypt_string(after_colon)

                        print('\n',before_colon,':',decryted_password,'\n')
                else:
                    print("No Passwords Stored")
        except FileNotFoundError:
            print("File not found:")
        except Exception as e:
            print(f"An error occurred: {e}")    

    
    def Add(url, username, new_password):
        
        try:
            encrypted_password = encrypt_string(new_password)
        
            with open(file_path, 'a') as file:
                file.seek(0, 2)  
                file.write('\n')
                file.write(f'{url}-> {username}:{encrypted_password}')
                print("Password Added successfully")
        except FileNotFoundError:
            print("Error: File not found at {filepath}")
        except Exception as e:
            print(f"An error occurred: {e}")



    
    


    def delete_line(username, login_id):
        try:
            #file_path = file_path
            with open(file_path, 'r') as file:
                lines = file.readlines()

            with open(file_path, 'w') as file:
                for line in lines:
                    if username in line and login_id in line:
                        continue  # Skip the line to delete
                    file.write(line)
                    print("Password Deleted")
        
            
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
        except Exception as e:
            print(f"An error occurred: {e}")

    if x==1:
        Add(input("Enter the Website URL: "),input("Enter the Login or User Id for the website: "),input("Enter the the password in plain text: "))
    elif x==2:
        delete_line(input("Enter the website URL: "),input("Enter the Login Id /User Id for the webiste: "))
    elif x==3:
        View()
    else:
        print("Invalid input")


if os.path.getsize(file_path) == 0:
    print("\033[3;5;4;37;41mWELCOME TO PASSWD\033[0m")
    print("\033[1;3;97mA \033[1;3;97mmaster key\033[1;3;97m is required to access and save the passwords. Ensure you have a strong master key for enhanced security.\033[0m")


    SetVaultKey()

key=OpenVault()
while True:
        print("Menu:")
        print("1. Generate Strong Password")
        print("2. Add Password")
        print("3. Delete Password")
        print("4. View Passwords")
        print("5. Exit")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            generate()
        elif choice == '2':
            Storage(1)
        elif choice == '3':
            Storage(2)
        elif choice == '4':
            Storage(3)
        elif choice=='5':
            print("Exited the program.")
            break

        else:
            print("Invalid choice. Please enter a number between 1 and 4.")



    
