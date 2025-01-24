import random
import string
import os
from cryptography.fernet import Fernet

# Get the path to the user's Documents folder
DOCUMENTS_FOLDER = os.path.expanduser("~/Documents")
PASSWORD_FILE_PATH = os.path.join(DOCUMENTS_FOLDER, "passwords.txt")

# Ensure the Documents folder exists (usually exists on all systems)
if not os.path.exists(DOCUMENTS_FOLDER):
    os.makedirs(DOCUMENTS_FOLDER)

# Generates a new encryption key
def generate_key():
    return Fernet.generate_key()

# Save the encryption key to a file
def save_key(key):
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)

# Load the encryption key from the file
def load_key():
    with open("encryption_key.key", "rb") as key_file:
        return key_file.read()

# Encrypt the data using the key
def encrypt_message(message, key):
    # Create a Fernet cipher object with the given key
    f = Fernet(key)
    # Encrypt the message by encoding it as bytes, encrypting, and then decoding the result to a string
    return f.encrypt(message.encode()).decode()

# Decrypt the encrypted data using the key
def decrypt_message(encrypted_message, key):
    # Create a Fernet cipher object with the given key
    f = Fernet(key)
    # Decrypt the encrypted message by encoding it as bytes, decrypting, and then decoding the result to a string
    decrypted_message = f.decrypt(encrypted_message.encode())
    return decrypted_message.decode()

# Function to generate a password with options to change the length, include numbers, and special characters.
def generate_password(min_length=15, numbers=True, special_characters=True):
    # All letters 
    letters = string.ascii_letters
    # All digits
    digits = string.digits
    # All punctuation except for hyphens
    special = string.punctuation.replace('-', '')

    # Creates a single string with all possible values depending on user options.
    characters = letters
    if numbers:
        characters += digits
    if special_characters:
        characters += special

    # Sets our current password as empty
    pwd = ""
    # Makes sure the password includes at least one digit or special char if they are enabled.
    meets_criteria = False
    has_number = False
    has_special = False
    checks = False

    # While not meeting the criteria or the current generated password is less than the desired length.
    while not meets_criteria or len(pwd) < min_length:
        # Picks a random choice out of all the possible characters.
        new_char = random.choice(characters)

        # Checks to make sure the character is not a hyphen
        if not new_char == "-":
            # Adds the new character to the password
            pwd += new_char
            checks = True

        # If the current char isn't a hyphen then proceed
        if checks:
            # If the current new char is a digit or if it is a special character set their respective check to true.
            if new_char in digits:
                has_number = True
            elif new_char in special:
                has_special = True

        # Set the meets_criteria value to true and then attempt to disprove.
        meets_criteria = True
        # If numbers are enabled and theres a number in the current generated password then meets_criteria is True.
        if numbers:
            meets_criteria = has_number
        # If special characters are enabled and is within the generated password, as well as checking for digits, then meets_criteria is True. Else if either digits and special character is enabled but either isn't included then meets_criteria is false.
        if special:
            meets_criteria = meets_criteria and has_special

    # Adds a hyphen after every 5 characters
    final_pwd = '-'.join([pwd[i:i+5] for i in range(0, len(pwd), 5)])
    # Returns the password generated
    return final_pwd

# Function to save the password with all inputted information to the file
def save_password(website, email, password, key):
    # Strips the website input of any white space
    website = website.strip()
    encrypted_email = encrypt_message(email, key)
    encrypted_password = encrypt_message(password, key)
    
    with open(PASSWORD_FILE_PATH, "a") as file:
        file.write(f"{website}, {encrypted_email}, {encrypted_password}\n")

# Function to retrieve all information about the inputted site
def retrieve_password(website, key):
    # Strips the website input of any white space
    website = website.strip()
    with open(PASSWORD_FILE_PATH, "r") as file:
        for line in file:
            parts = line.strip().split(', ')
            if parts[0] == website:
                decrypted_email = decrypt_message(parts[1], key)
                decrypted_password = decrypt_message(parts[2], key)
                return f"Website: {website}, Email: {decrypted_email}, Password: {decrypted_password}"
    return None

# Function to remove all information for the given website, with a confirmation prompt
def remove_password(website, key):
    # Trim any extra spaces from the website name
    website = website.strip()

    # Read all lines from the passwords file
    with open(PASSWORD_FILE_PATH, "r") as file:
        lines = file.readlines()

    removed_info = None

    # Open the passwords file in write mode to remove the specified website's information
    with open(PASSWORD_FILE_PATH, "w") as file:
        # Iterate through each line in the file
        for line in lines:
            # Split the line into parts using comma as the delimiter
            parts = line.strip().split(', ')
            # If the first part (website name) matches the specified website
            if parts[0] == website:
                # Decrypt the email and password stored in the line
                decrypted_email = decrypt_message(parts[1], key)
                decrypted_password = decrypt_message(parts[2], key)
                # Store the information to be removed
                removed_info = f"Website: {website}, Email: {decrypted_email}, Password: {decrypted_password}"
                # Continue to the next line without writing this line to the file
                continue
            # Write the line to the file if it's not the one to be removed
            file.write(line)

    # If information was found to be removed
    if removed_info:
        # Print the information to be removed
        print("Information to be removed:")
        print(removed_info)
        # Ask for confirmation before removing
        confirmation = input("Are you sure you want to remove this information? (y/n): ")
        if confirmation.lower() == 'y':
            print("Information removed.")
        else:
            # If the user decides to cancel then readd the information
            print("Removal canceled.")
            # Reopen the password.txt file and append the information back
            with open("passwords.txt", "a") as file:
                save_password(website, decrypted_email, decrypted_password, key)
    else:
        # If no information was found for the given website
        print("No information found for the given website.")


# Function to generate a new encryption key if one doesn't exist
def generate_or_load_key():
    key_file_path = "encryption_key.key"
    if os.path.exists(key_file_path):
        with open(key_file_path, "rb") as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(key_file_path, "wb") as key_file:
            key_file.write(key)
    return key

def main():
    # Load or generate the encryption key
    key = generate_or_load_key()
    
    # Check if the password file exists, if not then create one
    if not os.path.exists("passwords.txt"):
        open("passwords.txt", "w").close()

    while True:
        # Get the option choice of the user
        option = input("Enter '1' to generate a new password, or '2' to retrieve information about a site, or '3' to remove information for a site: ")

        # If they choose to generate a new password 
        if option == '1':
            # Get the user to input the following data. (Website + email)
            website = input("Enter the website name: ")
            email = input("Enter the email address: ")

            # Generates the password 
            generated_password = generate_password()

            # Shows that the password has been generated
            print("Generated Password:", generated_password)

            # Uses the save password function to save this all to the password text file
            save_password(website, email, generated_password, key)

            # Shows that the password has saved to the file
            print("Password saved to file.")


        # Else if they choose to retrieve all information for a website
        elif option == '2':
            # Get the website name
            website = input("Enter the website name to retrieve information: ")

            # Search for the information using the website name
            retrieved_info = retrieve_password(website, key)

            # If it the data for that site exists
            if retrieved_info:
                # Print the saved information
                print("Information retrieved:", retrieved_info)
            else:
                print("No information found for the given website.")
        
        # Else if the users chooses to remove all information for a given website
        elif option == '3':
            # Get the website name
            website = input("Enter the website name to remove information: ")
            remove_password(website, key)

        # Else they inputted an invalid option
        else:
            print("Invalid option.")

        # Reaasks the user if they want to continue using the program, if not then the program quits
        reask = input("Would you like to perform another action? (y/n): ")
        if reask.lower() != 'y':
            print("Quitting program...")
            break

# Ensures the code isnt executed unless it is run directly
if __name__ == "__main__":
    main()