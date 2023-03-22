import sys
import os
import PyQt5.QtCore
from PyQt5.QtGui import QFont
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import hashlib
import struct
import base64
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QMessageBox, QLineEdit, QPushButton, QFileDialog, QInputDialog, QTextEdit, QScrollArea, QVBoxLayout, QWidget, QHBoxLayout


print(PyQt5.QtCore.qVersion())


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.filepaths = []
        self.error = False
        # Set the window title and size
        self.setWindowTitle('File Encryption Tool')
        self.setGeometry(100, 100, 400, 500)
        self.setStyleSheet('background-color: #2b2b2b; color: white;')

        # Set the font for the UI
        font = QFont('Roboto', 12)
        self.setFont(font)

        # Create the select file and select folder buttons
        self.btnSelectFile = QPushButton('Add File(s)', self)
        self.btnSelectFile.setStyleSheet(
            'background-color: #007bff; color: white;  border-radius:2px; padding: 5px 10px;')
        self.btnSelectFolder = QPushButton('Add Folder(s)', self)
        self.btnSelectFolder.setStyleSheet(
            'background-color: #007bff; color: white;border-radius:2px; padding: 5px 10px;')
        self.btnEncrypt = QPushButton('Encrypt', self)
        self.btnEncrypt.setStyleSheet(
            'background-color: #007bff; color: white;border-radius:2px; padding: 5px 10px;')
        self.btnDecrypt = QPushButton('Decrypt', self)
        self.btnDecrypt.setStyleSheet(
            'background-color: #007bff; color: white;border-radius:2px; padding: 5px 10px;')
        self.clear_button = QPushButton("Clear All", self)
        self.clear_button.setStyleSheet(
            'background-color: #007bff; color: white;border-radius:2px; padding: 5px 10px;')

        # Create the file/folder path label and text field
        self.lblFilepath = QLabel('File/Folder path:', self)
        self.lblFilepath.setStyleSheet('margin-top: 20px;')

        self.txtFilepath = QTextEdit(self)
        self.txtFilepath.setReadOnly(True)
        self.txtFilepath.setStyleSheet(
            'background-color: #3b3b3b; color: white;')
        self.txtFilepath.setMaximumHeight(150)

        # Create the errors label and text field
        self.lblErr = QLabel('Errors:', self)
        self.lblErr.setStyleSheet('margin-top: 20px;')

        self.txtErr = QTextEdit("No errors found!", self)
        self.txtErr.setReadOnly(True)
        self.txtErr.setStyleSheet('background-color: black; color: red;')
        self.txtErr.setMaximumHeight(150)

        # Create the main layout and add the widgets
        main_layout = QVBoxLayout()
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.btnSelectFile)
        button_layout.addWidget(self.btnSelectFolder)
        button_layout.addWidget(self.btnEncrypt)
        button_layout.addWidget(self.btnDecrypt)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.clear_button)
        main_layout.addWidget(self.lblFilepath)
        main_layout.addWidget(self.txtFilepath)
        main_layout.addWidget(self.lblErr)
        main_layout.addWidget(self.txtErr)

        # Set the main layout for the window
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # # Connect signals and slots
        self.clear_button.clicked.connect(self.clear_text_edit)
        self.btnSelectFile.clicked.connect(self.select_file)
        self.btnSelectFolder.clicked.connect(self.select_folder)
        self.btnEncrypt.clicked.connect(self.encrypt_file)
        self.btnDecrypt.clicked.connect(self.decrypt_file)

    def select_file(self):
        # Show file dialog to choose files
        filepaths, _ = QFileDialog.getOpenFileNames(
            self, 'Select File(s)', '', 'All Files (*)')

        for filepath in filepaths:
            if filepath not in self.filepaths:
                self.filepaths.append(filepath)

        self.txtFilepath.clear()
        for i, filepath in enumerate(self.filepaths):
            self.txtFilepath.insertPlainText(f"{i+1}: {filepath}\n")
            # self.txtFilepath.setText(';'.join(filepaths))

    def select_folder(self):
        # some  pyqt versions does not support selecting multiple folders
        # folder_paths = QFileDialog.getExistingDirectories(
        # self, 'Select Folders', '', QFileDialog.ShowDirsOnly)
        folder_path = QFileDialog.getExistingDirectory(
            self, 'Select Folder', '')
        if not folder_path:
            return
        if folder_path not in self.filepaths:
            self.filepaths.append(folder_path)

        self.txtFilepath.clear()
        for i, filepath in enumerate(self.filepaths):
            self.txtFilepath.insertPlainText(f"{i+1}: {filepath}\n")

    def clear_text_edit(self):
        self.filepaths = []
        self.txtFilepath.clear()
        self.txtErr.clear()
        self.error = False

    def encrypt_file(self):
        # Check if files have been selected
        self.txtErr.clear()
        self.error = False
        if not self.filepaths:
            QMessageBox.warning(
                self, 'Error', 'Please select one or more files or a directory')
            return

        # Get password from user
        password, ok = QInputDialog.getText(
            self, 'Enter Password', 'Enter Password:', QLineEdit.Password)
        if not ok:
            return

        # Encrypt files / folders
        encrypted_files = []
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
                            if skip == filepath:
                                pass
                            else:
                                self.encrypt_file_helper(filepath, password)
                                encrypted_files.append(filepath)

        QMessageBox.information(
            self, '', 'Encryption complete')
        if not self.error:
            self.txtErr.clear()
            self.txtErr.insertPlainText('No errors found!')

        encrypted_files = []

    def decrypt_file(self):
        self.txtErr.clear()
        self.error = False
        # Check if files have been selected
        if not self.filepaths:
            QMessageBox.warning(
                self, 'Error', 'Please select one or more files or a directory')
            return

        # Get password from user
        password, ok = QInputDialog.getText(
            self, 'Enter Password', 'Enter Password:', QLineEdit.Password)
        if not ok:
            return

        # Decrypt files
        decrypted_files = []
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

        if not self.error:
            QMessageBox.information(
                self, '', 'Decryption complete')
        if not self.error:
            self.txtErr.clear()
            self.txtErr.insertPlainText('No errors found!')

        decrypted_files = []

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

            #  # Write the password to a separate file
            # with open(output_file_path + ".pwd", 'w') as pwd_file:
            #     encoded_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            #     pwd_file.write(encoded_password)

        except Exception as e:
            print(e)
            self.txtErr.insertPlainText(
                'Error:   ' + filepath + ' ::: ' + str(e) + '\n')
            self.error = True

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
            except InvalidToken as e:
                print('The provided password is incorrect.')

                self.txtErr.insertPlainText(
                    'Error:   ' + filepath + '::: Incorrect Password!' + '\n')
                self.error = True
                return
            except Exception as e:
                print(e)

                self.txtErr.insertPlainText(
                    'Error:   ' + filepath + ' ::: ' + str(e) + '\n')
                self.error = True
                return

            # Write the decrypted data to the output file
            with open(filepath, 'wb') as output_file:
                output_file.write(decrypted_data)

        except Exception as e:
            print(e)
            print(f'An error occurred: {filepath}::: {e}')

            self.txtErr.insertPlainText(
                'Error:   ' + filepath + ' ::: ' + str(e) + '\n')
            self.error = True

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
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()
