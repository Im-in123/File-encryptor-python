from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import hashlib
import struct
import base64
import os
import sys


class Encryptor:
    def __init__(self):

        self.filepaths = []
        self.error = True

    def encrypt_file(self):
        if not self.filepaths:
            print("Please select one or more files or directories! \n")
            return
        encrypted_files = []
        print("Encryption list:", self.filepaths)
        password = input("Enter password:")
        print("Encrypting ... \n")
        skip = self.skip_executor()

        for filepath in self.filepaths:
            if os.path.isfile(filepath):
                if filepath not in encrypted_files:
                    if skip == filepath:
                        pass
                    else:
                        self.encrypt_file_helper(filepath, password)
                        encrypted_files.append(filepath)
            elif os.path.isdir(filepath):
                for foldername, subfolders, filenames in os.walk(filepath):
                    for filename in filenames:
                        filepath = os.path.join(foldername, filename)
                        if filepath not in encrypted_files:
                            skip = self.skip_executor()
                            if skip == filepath:
                                pass
                            else:
                                self.encrypt_file_helper(filepath, password)
                                encrypted_files.append(filepath)
            else:
                print(f"{filepath} not found!")
        encrypted_files = []
        if not self.error:
            print("Encryption complete! \n")
        else:
            print("There were some errors encountered while encrypting!")

    def encrypt_file_helper(self, filepath, password):
        try:
            """
    Encrypts the input file using an encryption key derived from the password,
    and saves the encryption key (password) in the output file.
    """
            # Derive the encryption key from the password
            password_bytes = password.encode('utf-8')
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
                backend=default_backend()
            )
            encryption_key = base64.urlsafe_b64encode(
                kdf.derive(password_bytes))

            # Encrypt the input file data using the encryption key
            f = Fernet(encryption_key)
            with open(filepath, 'rb') as input_file:
                input_data = input_file.read()
                encrypted_data = f.encrypt(input_data)

            # Save the encryption key (password), the salt, and the encrypted data in the output file
            with open(filepath, 'wb') as output_file:
                salt_size = struct.pack('<I', len(salt))
                output_file.write(salt_size)
                output_file.write(salt)
                output_file.write(encrypted_data)
            print(f"{filepath} encrypted successfully")
            #  # Write the password to a separate file
            # with open(output_file_path + ".pwd", 'w') as pwd_file:
            #     encoded_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            #     pwd_file.write(encoded_password)

        except Exception as e:
            print('Error:   ' + filepath + ' ::: ' + str(e) + '\n')
            self.error = True

    def decrypt_file(self):
        if not self.filepaths:
            print("Please select one or more files or directories! \n")
            return
        decrypted_files = []
        print("Decryption list:", self.filepaths)

        password = input("Enter password:")
        print("Decrypting ... \n")
        skip = self.skip_executor()

        for filepath in self.filepaths:
            if os.path.isfile(filepath):
                if filepath not in decrypted_files:
                    if skip == filepath:
                        pass
                    else:
                        self.decrypt_file_helper(filepath, password)
                        decrypted_files.append(filepath)

            elif os.path.isdir(filepath):
                for foldername, subfolders, filenames in os.walk(filepath):
                    for filename in filenames:
                        filepath = os.path.join(foldername, filename)
                        if filepath not in decrypted_files:
                            if skip == filepath:
                                pass
                            else:
                                self.decrypt_file_helper(filepath, password)
                                decrypted_files.append(filepath)
        decrypted_files = []
        if not self.error:
            print("Decryption complete! \n")
        else:
            print("There were some errors encountered while decrypting!")

    def decrypt_file_helper(self, filepath, password):
        try:
            with open(filepath, 'rb') as input_file:
                salt_size = struct.unpack('<I', input_file.read(4))[0]
                salt = input_file.read(salt_size)
                encrypted_data = input_file.read()

            # Derive the encryption key from the password and salt
            password_bytes = password.encode('utf-8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
                backend=default_backend()
            )
            encryption_key = base64.urlsafe_b64encode(
                kdf.derive(password_bytes))

            #  # Verify the password
            # with open(input_file_path + ".pwd", 'r') as pwd_file:
            #     encoded_password = pwd_file.read().strip()
            #     if hashlib.sha256(password.encode('utf-8')).hexdigest() != encoded_password:
            #         print('The provided password is incorrect 2.')
            #         return
            #     else:
            #         print('The password is correct.')

            # Decrypt the input file data using the encryption key
            f = Fernet(encryption_key)
            try:
                decrypted_data = f.decrypt(encrypted_data)
                print(f"{filepath} decrypted successfully")
            except InvalidToken as e:
                print('Error:   ' + filepath + '::: Incorrect Password!' + '\n')
                self.error = True
                return
            except Exception as e:
                print('Error:   ' + filepath + ' ::: ' + str(e) + '\n')
                self.error = True
                return

            # Write the decrypted data to the output file
            with open(filepath, 'wb') as output_file:
                output_file.write(decrypted_data)

        except Exception as e:
            print(e)
            print(f'An error occurred: {filepath}::: {e}')
            self.error = True

    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                dirs.append(os.path.join(dir_path, fname))
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        # print(dirs)
        self.filepaths = dirs
        self.encrypt_file()
        if not self.error:
            print(
                "Encrypted all files and folders in the current directory of the program!\n")

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        self.filepaths = dirs
        self.decrypt_file()
        if not self.error:
            print(
                "Decrypted all files and folders in the current directory of the program!\n")

    def clear(self): return os.system('cls')

    def run(self):
        numbs = [1, 2, 3, 4, 5]
        while True:
            self.filepaths = []
            self.error = False
            manual = "1. Press '1' to encrypt file.\n2. Press '2' to decrypt file.\n3. Press '3' to Encrypt all files in the  current of the program..\n4. Press '4' to decrypt all files in the current directory of the program.\n5. Press '5' to exit."
            print(manual)
            choice = input(">> ")

            # if isinstance(choice, int):
            try:
                choice = int(choice)
                if choice in numbs:

                    self.clear()

                    if choice == 1:
                        files_input = input(
                            "Enter name of files or folders to encrypt separated by ','. :>> ")
                        files_list = files_input.split(',')
                        for f in files_list:
                            if f.strip() != '':
                                self.filepaths.append(f)
                        self.encrypt_file()

                    elif choice == 2:
                        files_input = input(
                            "Enter name of files or folders to decrypt separated by ','. :>> ")
                        files_list = files_input.split(',')
                        for f in files_list:
                            if f.strip() != '':
                                self.filepaths.append(f)
                        self.decrypt_file()

                    elif choice == 3:
                        self.encrypt_all_files()
                    elif choice == 4:
                        self.decrypt_all_files()
                    elif choice == 5:
                        print("Exiting... done")
                        exit()
                    else:
                        print("Please select a valid option!")
                else:
                    print("Please select a valid option!")
            except Exception as e:
                print("Choice should be a number!")
                print(e)

    def skip_executor(self):

        # determine if application is a script file or frozen exe
        if getattr(sys, 'frozen', False):
            source_file = os.path.realpath(sys.executable)
            ext = ".exe"
            return source_file

        elif __file__:
            source_file = os.path.realpath(__file__)
            basename = os.path.basename(source_file)
            ext = os.path.splitext(basename)[1]

        return source_file


if __name__ == '__main__':
    app = Encryptor()
    app.run()
