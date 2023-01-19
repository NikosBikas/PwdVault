import string
import secrets
import base64
import csv
import os,sys,platform, os.path, time
from getpass import getpass
from prettytable import PrettyTable
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Global Variables
# 
password = None
salt = None
key = None

# Function that Checks User OS For Clearing The Screen
def clear():
	if(platform.system() == "Windows"): #Checking User OS For Clearing The Screen
		os.system('cls') 
	else:
		os.system('clear')

def print_banner(title="Python PassWord Vault 0.01 by Nikolaos Bikas"):
    print("""
██████╗ ██╗    ██╗██████╗ ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
██╔══██╗██║    ██║██╔══██╗██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
██████╔╝██║ █╗ ██║██║  ██║██║   ██║███████║██║   ██║██║     ██║   
██╔═══╝ ██║███╗██║██║  ██║╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
██║     ╚███╔███╔╝██████╔╝ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
╚═╝      ╚══╝╚══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝                   
""")
    total_len = 67
    if title:
        padding = total_len - len(title) - 4
        print("= {} {}\n".format(title, "=" * padding))
    else:
        print("{}\n".format("=" * total_len)) 
 
## Initial Check
def initial_check():
    seach_for_salt()
    search_for_key()
    search_for_vault()
    
    
    
 
#Create a password for the vault 
def create_vault_password():
    print_banner("Welcome to PwDVault. Please choose a secure secret key.")
    count = 0
    while True:
        password = getpass("Please choose a master key: ")
        if len(password) < 8:
            count+=1
            print('The master key should be at least 8 characters. Please try again!')
            if count>=3:
                print('More that 3 failed tries exiting...')
                exit()    
            continue
        password_confirm = getpass("Please confirm your master key: ")
        if password_confirm != password:
            print("The master key does not match its confirmation. Please try again!")
            continue
        else:
            password = password.encode()
            with open('Data/.salt', 'r') as salt:
                salt01 = salt.read().encode()
                kdf = PBKDF2HMAC (
                    algorithm=hashes.SHA256,
                    length=32,
                    salt=salt01,
                    iterations=100000,
                    backend=default_backend()
                )
                original_stdout = sys.stdout
                with open('Keys/vault.key', 'w') as vault_key:
                    sys.stdout = vault_key
                    print(base64.urlsafe_b64encode(kdf.derive(password)).decode())
                    sys.stdout = original_stdout
                    print('Key was Generated Succefully!')
                salt.close()
            break
                
def generate_salt():
    original_stdout = sys.stdout
    with open('Data/.salt', 'w') as hiden_salt:
        sys.stdout = hiden_salt
        print(os.urandom(16))
        sys.stdout = original_stdout
        hiden_salt.close()
        print('Salt was Generated Succefully!')
        create_vault_password()
    
# def create_password():
#     with open('Data/.salt', 'r') as salt:
#         salt01 = salt.read().encode()
#         print(salt01)
        
#         password = '123456789'.encode()
        
#         kdf = PBKDF2HMAC (
#             algorithm=hashes.SHA256,
#             length=32,
#             salt=salt01,
#             iterations=100000,
#             backend=default_backend()
#         )
        
    
#     key = base64.urlsafe_b64encode(kdf.derive(password))
#     print(key.decode())


# Search for salt
def seach_for_salt():
    salt_exists = os.path.exists('Data/.salt')
    if salt_exists:
        print("Salt found!")
        print_banner("Vault login!")
        count = 0
        password = None
        while True:
            password = getpass("Enter your master key: ")
            if len(password) < 8:
                count+=1
                print('The master key should be at least 8 characters. Please try again!')
                if count>=3:
                    print('More that 3 failed tries exiting...')
                    exit()    
                continue
            password = password.encode()
            with open('Data/.salt', 'r') as salt:
                salt01 = salt.read().encode()
                kdf = PBKDF2HMAC (
                    algorithm=hashes.SHA256,
                    length=32,
                    salt=salt01,
                    iterations=100000,
                    backend=default_backend()
                )
                
                generated_key = base64.urlsafe_b64encode(kdf.derive(password)).decode()
                with open('Keys/vault.key', 'r') as key:
                    key01 = key.read().strip()
            if generated_key == key01:
                print("Succes")
                break
            else:
                print("The master key does not match its confirmation. Please try again!")
                input("")
                continue          
    else:
        print("Salt was not found lets create it!")
        generate_salt()
        
    

# Search for encryption key file in Keys Folder
def search_for_key():
    key_exists = os.path.exists('Keys/vault.key')
    if key_exists:
        print("Key found!")
        print_banner("Enter Vault Password!")
        
    else:
        print("Key was not found lets create it!")
        key = Fernet.generate_key()
        with open('Keys/vault.key', 'wb') as enc:
            enc.write(key)

def search_for_vault():
    data_exists = os.path.exists('Data/vault01.csv')
    if data_exists:
        print('Data file found!')
    else:
        with open('Data/vault01.csv', mode='w') as csv_file:
            data_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        encrypt_data()

def encrypt_data():
    # opening the key
    with open('Keys/vault.key', 'rb') as filekey:
        key = filekey.read()

    # using the generated key
    fernet = Fernet(key)
    
    # opening the original file to encrypt
    with open('Data/vault01.csv', 'rb') as file:
        original = file.read()
        
    # encrypting the file
    encrypted = fernet.encrypt(original)

    # opening the file in write mode and
    # writing the encrypted data
    with open('Data/vault01.csv', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)


def decrypt_data():   
    # opening the key
    with open('Keys/vault.key', 'rb') as filekey:
        key = filekey.read()
         
    # using the key
    fernet = Fernet(key)
    
    # opening the encrypted file
    with open('Data/vault01.csv', 'rb') as enc_file:
        encrypted = enc_file.read()
    
    # decrypting the file
    decrypted = fernet.decrypt(encrypted)
    
    # opening the file in write mode and
    # writing the decrypted data
    with open('Data/vault01.csv', 'wb') as dec_file:
        dec_file.write(decrypted)
    
def delete_vault():
    print_banner("Delete Vault...")
    choice = input("Do you want to delete the Vault?(y/n): ")
    if choice == 'y':
        print('Removing Salt file...')
        os.remove('Data/.salt')
        print('Done!')
        print('Removing Vault file...')
        os.remove('Data/vault01.csv')
        print('Done!')
        print('Removing Key...')
        os.remove('Keys/vault.key')
        print('Done!')
        input('Press any key to exit the app!')
        exit()
    if choice == 'n':
        input("Enter any key to return at the main menu!")
        main_menu()
    else:
        input("Invalid option returning at the main menu...")
        main_menu()
        
        
        

def add_password():
    clear()     
    print_banner("New Entry...")
    print("")
    id = None
    website = input("Enter a Website name eg. facebook: ")
    email = input("Enter email: ")
    password_gen = random_password_ganerator()
    print("Sujected random password: "+password_gen)
    password = input("Enter Password: ").strip()
    decrypt_data()
    with open('Data/vault01.csv', mode='a') as csv_file:
        data_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        id = 1
        for row in open("Data/vault01.csv"):
            id+=1
        data_writer.writerow([id,website,email,password])
        csv_file.close()
    encrypt_data()
    clear()     
    print_banner("New entry added succefuly! ")
    input("Press Enter to return at the Main Menu...")
    return password_manager_submenu()
    
def display_data():
    print_banner("Data table...")
    x = PrettyTable()
    x.field_names = ['id','website', 'email', 'password']
    decrypt_data()
    with open('Data/vault01.csv') as f:
        line = f.readline()
        while line:
            x.add_row(line.rstrip().split(','))
            line = f.readline()
    print(x)
    encrypt_data()
    print("") 
    input("Press Enter to return at the Main Menu...")
    return password_manager_submenu()
          
def random_password_ganerator():
    length = 15
    password = ''.join(secrets.choice(string.ascii_lowercase + string.digits + string.punctuation)for _ in range(length))
    return password


def view_notes():
    clear()
    print_banner()
    print("Under Construction")
    input("Press any key to return at the menu")
    notes_manager_submenu()

def add_new_note():
    clear()
    print_banner()
    print("Under Construction")
    input("Press any key to return at the menu")
    notes_manager_submenu()
# =======================
#     MENUS FUNCTIONS
# =======================

# Main menu
def main_menu():
    clear()
    print_banner()
    print ("Main Menu:")
    print ("")
    print ("1 Password Manager. ")
    print ("2 Notes Manager. ")
    print ("3 Encrypt Data")
    print ("4 Decrypt Data")
    print ("5 Erase Vault!")
    print ("0 Quit")
    print ("")
    choice = input("Enter your choice: ")
    exec_menu(choice)
    return

# Execute Main Menu
def exec_menu(choice):
    clear()
    ch = choice.lower()
    if ch == '':
        menu_actions['main_menu']()
    else:
        try:
            menu_actions[ch]()
        except KeyError:
            print_banner()
            print ("Invalid selection, please try again.\n")
            time.sleep(2)
            menu_actions['main_menu']()
    return

# Password_Manager_Submenu
def password_manager_submenu():
    clear()
    print_banner()
    print ("Password Manager:")
    print ("")
    print ("1 Display Passwords. ")
    print ("2 New Entry. ")
    print ("3 Return at the main menu.")
    print ("0 Quit")
    print ("")
    choice = input("Enter your choice: ")
    exec_password_manager_submenu(choice)
    return

# Execute password management menu
def exec_password_manager_submenu(choice):
    clear()
    ch = choice.lower()
    if ch == '':
        sub_menu_password_actions['password_manager_submenu']()
    else:
        try:
            sub_menu_password_actions[ch]()
        except KeyError:
            print_banner()
            print ("Invalid selection, please try again.\n")
            time.sleep(2)
            sub_menu_password_actions['password_manager_submenu']()
    return

# Notes_Manager_Submenu
def notes_manager_submenu():
    clear()
    print_banner()
    print ("Notes Manager:")
    print ("")
    print ("1 View Notes. ")
    print ("2 Add New Note. ")
    print ("3 Return at the main menu.")
    print ("0 Quit")
    print ("")
    choice = input("Enter your choice: ")
    exec_notes_manager_submenu(choice)
    return

# Execute notes management menu
def exec_notes_manager_submenu(choice):
    clear()
    ch = choice.lower()
    if ch == '':
        sub_menu_notes_actions['notes_manager_submenu']()
    else:
        try:
            sub_menu_notes_actions[ch]()
        except KeyError:
            print_banner()
            print ("Invalid selection, please try again.\n")
            time.sleep(2)
            sub_menu_notes_actions['notes_manager_submenu']()
    return

# Exit program
def exit():
    sys.exit()

# =======================
#    MENUS DEFINITIONS
# =======================

# Menu definitions
menu_actions = {
    'main_menu': main_menu,
    '1': password_manager_submenu,
    '2': notes_manager_submenu,
    '3': encrypt_data,
    '4': decrypt_data,
    '5': delete_vault,
    '0': exit,
}

# Sub_menu_password definitions
sub_menu_password_actions = {
    'password_manager_submenu': password_manager_submenu,
    '1': display_data,
    '2': add_password,
    '3': main_menu,
    '0': exit,
}

sub_menu_notes_actions = {
    'notes_manager_submenu': notes_manager_submenu,
    '1': view_notes,
    '2': add_new_note,
    '3': main_menu,
    '4': exit,
}


# =======================
#      MAIN PROGRAM
# =======================

# Main Program
if __name__ == "__main__":
    # Launch main menu
    initial_check()
    main_menu()