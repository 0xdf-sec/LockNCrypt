import os
import sys
import re
import random
import time
import logging
import threading
import shutil
import pyotp        # library used for generating and verifying OTPs
import qrcode       # used for generating QR codes
import tkinter as tk        # Heps in GUI  popups and file selection process
from tkinter import filedialog, messagebox, ttk     # Helps GUI elements for file selection and messages  to users
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding      # Adds/removes padding for encryption 
from telesign.messaging import MessagingClient
import subprocess
import psutil


""" Constants for storing secret key and credentials like api key and customer id from terminal """
SECRET_KEY = "TOTP_SECRET_KEY"
PHONE_NUMBER = os.getenv("PHONE_NUMBER")        # Get phone number from environment adn if its the first run then it will ask the user and stores in the windows env.
TELESIGN_CUSTOMER_ID = os.getenv("TELESIGN_CUSTOMER_ID")      # Get Telesign ID and stores it in windows envsame like phone number
TELESIGN_API_KEY = os.getenv("TELESIGN_API_KEY")        # Get Telesign API key and stores it in windows envsame like phone number


logging.basicConfig(filename='otp_attempts.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# INPUT VALIDATION
def validate_input(input_str, input_type):
    if not input_str:
        raise ValueError("Input cannot be empty.")

    if input_type == "api_key" or input_type == "customer_id":
        if not re.match(r"^[a-zA-Z0-9\-_=/+]+$", input_str):        #A.I. Generated
            raise ValueError(f"Invalid {input_type}: Must contain only alphanumeric characters, hyphens, underscores, equal signs, forward slashes, and plus signs.")
        if len(input_str) > 100:
            raise ValueError(f"Invalid {input_type}: Must be 100 characters or less.")
    elif input_type == "phone_number":
        if not re.match(r"^\+?[0-9]+$", input_str):         #A.I. Generated
            raise ValueError("Invalid phone number: Must contain only digits and an optional '+'.")
        if len(input_str) > 15:
            raise ValueError("Invalid phone number: Must be 15 characters or less.")
    else:
        raise ValueError("Invalid input type for validation.")

    return input_str

#A.I. Generated
class EnvironmentManager:       # Class that Handles environment variable setup
    @staticmethod
    def set_environment_variable(name, value):
        try:
            if sys.platform == "win32":
                subprocess.run(['setx', name, value], check=True)        # Set env variable on Windows 
            else:
                with open(os.path.expanduser('~/.bashrc'), 'a') as f:       #  Open the .bashrc file in append mode
                    f.write(f'export {name}="{value}"\n')       # Append variable to .bashrc (Linux/Mac)
                subprocess.run(['source', os.path.expanduser('~/.bashrc')], check=True, shell=True)      # pdate the current shell session with the new variable
        except subprocess.CalledProcessError as e:
            print(f"Error setting environment variable {name}: {e}")         # Print error if setting fails

    @staticmethod
    def prompt_for_env_vars():       # Function that Asks user for missing environment variables
        global PHONE_NUMBER, TELESIGN_CUSTOMER_ID, TELESIGN_API_KEY

        if not TELESIGN_CUSTOMER_ID:        # Check if TELESIGN_CUSTOMER_ID is not set
            while True:
                try:
                    TELESIGN_CUSTOMER_ID = input("Enter your Customer ID: ").strip()        # Prompt the user to enter the Telesign Customer ID
                    validate_input(TELESIGN_CUSTOMER_ID, "customer_id")
                    break
                except ValueError as e:
                    print(e)
            EnvironmentManager.set_environment_variable("TELESIGN_CUSTOMER_ID", TELESIGN_CUSTOMER_ID)        # Set the environment variable for TELESIGN_CUSTOMER_ID

        if not TELESIGN_API_KEY:
            while True:
                try:
                    TELESIGN_API_KEY = input("Enter your API Key: ").strip()         # Prompt the user to enter the Telesign API Key
                    validate_input(TELESIGN_API_KEY, "api_key")
                    break
                except ValueError as e:
                    print(e)
            EnvironmentManager.set_environment_variable("TELESIGN_API_KEY", TELESIGN_API_KEY)        # Set the environment variable for telesign_api_key

        if not PHONE_NUMBER:          # Check if PHONE_NUMBER is not set
            while True:
                try:
                    PHONE_NUMBER = input("Enter your phone number for OTP (including country code): ").strip()      # Prompt the user to enter their phone number for OTP
                    validate_input(PHONE_NUMBER, "phone_number")
                    break
                except ValueError as e:
                    print(e)
            EnvironmentManager.set_environment_variable("PHONE_NUMBER", PHONE_NUMBER)       # Set the environment variable for PHONE_NUMBER

class OTPManager:        # Class that Manages OTP authentication
    def __init__(self, secret=None):
        # RETRY LIMITS & ATTEMPTS
        self.secret = secret or self.get_or_generate_secret()        # Use existing secret or generate a new one 
        self.retry_limit = 3
        self.time_limit = 30

    def authenticate_user(self, root):       # Function that Asks for OTP and verifies it
        totp = pyotp.TOTP(self.secret)      
        attempts = 0

        while attempts < self.retry_limit:
            otp = self.get_totp_from_gui(root)
            if otp is None:
                print("Time limit exceeded. Exiting.")
                logging.warning("TOTP verification failed: Time limit exceeded.")
                sys.exit(1)

            if totp.verify(otp, valid_window=5):         # Check OTP with slight time flexibility
                print("Google/Microsoft Authenticator OTP verification successful!")
                logging.info("TOTP verification successful.")
                return True
            else:
                attempts += 1
                print(f"Invalid OTP. Attempts remaining: {self.retry_limit - attempts}")
                logging.warning(f"TOTP verification failed: Attempt {attempts}.")

        print("Maximum OTP attempts reached. Exiting.")
        logging.warning("TOTP verification failed: Maximum attempts reached.")
        sys.exit(1)

    def get_or_generate_secret(self):       # Function that Fetch or generate a new OTP secret key 
        secret = os.getenv(SECRET_KEY)
        if secret:
            print("Loaded existing secret key from environment.")
        else:
            print("No existing secret key found. Generating a new secret key.")
            secret = pyotp.random_base32()      # Generate a random base32 secret
            EnvironmentManager.set_environment_variable(SECRET_KEY, secret)
            print(f"Generated new secret key: {secret}")
            self.generate_qr_code(secret)        # Generate QR code for the new secret
        return secret

# A.I Generated
    def generate_qr_code(self, secret):      # Function that Creates QR code for Google/Microsoft Authenticator 
        totp = pyotp.TOTP(secret)       # Create a TOTP (Time-based One-Time Password) object using the provided 
        provisioning_uri = totp.provisioning_uri("YourAppName", issuer_name="YourIssuerName")       # Generate the provisioning URI for Authenticator
        print("Generating QR code for Google Authenticator...")
        qr = qrcode.QRCode()        # Create a QR code object
        qr.add_data(provisioning_uri)       # Add the provisioning URI to the QR code
        qr.make(fit=True)       # Adjust the QR code to fit the data
        img = qr.make_image(fill="black", back_color="white")       # Generate the QR code image with black fill and white background
        qr_filename = "authenticator_qr.png"
        img.save(qr_filename)
        print(f"QR code saved as {qr_filename}. Open it to scan with Google Authenticator.")

# A.I Generated
    def get_totp_from_gui(self, root):
        # Create a new top-level window on top of the main root window
        otp_window = tk.Toplevel(root)
        otp_window.title("Enter TOTP")
        otp_window.geometry("350x250")      # Create a new top-level window on top of the main root window

        # Instructional label prompting user for OTP
        label = tk.Label(otp_window, text="Enter the OTP from your Google/Microsoft Authenticator app:")
        label.pack(pady=10)

        # Entry widget for OTP input, styled with larger font for readability
        otp_entry = tk.Entry(otp_window, font=("Arial", 14))
        otp_entry.pack(pady=10)

        otp = None      # Placeholder for storing user input - It will be updated on submit

#A.I Geenrated
        def submit_otp():
            nonlocal otp        # Allows assignment to the outer variable 'otp' declared earlier in the parent function
            otp = otp_entry.get().strip()        # Get the text from the entry box and remove leading/trailing whitespace
            otp_window.destroy()         # Close the OTP entry popup after submission

# Create the submit button and bind it to the submit_otp function   
        submit_button = tk.Button(otp_window, text="Submit", command=submit_otp)
        submit_button.pack(pady=10)

# Countdown label that visually shows the time remaining to enter OTP
        countdown_label = tk.Label(otp_window, text=f"Time remaining: {self.time_limit} seconds", fg="red")
        countdown_label.pack(pady=10)       # Place the label with spacing below the Submit button

        def update_countdown(time_left):
            # Dynamically update the countdown label every second with the remaining time
            if time_left > 0:
                countdown_label.config(text=f"Time remaining: {time_left} seconds")
                otp_window.after(1000, update_countdown, time_left - 1)      # Schedule the update_countdown function to run again after 1 second (1000ms)
            else:
                otp_window.destroy()        

        update_countdown(self.time_limit)   # Start the countdown timer with the full time limit
        otp_window.wait_window()        # Wait here (block execution) until the OTP popup window is closed (either submit or timeout)
        return otp      # Return the OTP entered by the user (or None if closed without input)

    def get_phone_otp_from_gui(self, root):
        # Create a new popup window for phone OTP input
        otp_window = tk.Toplevel(root)
        otp_window.title("Enter Phone OTP")
        otp_window.geometry("350x200")

        label = tk.Label(otp_window, text="Enter the OTP sent to your phone:")       # Add a label instructing the user to input the OTP received via phone
        label.pack(pady=10)

        otp_entry = tk.Entry(otp_window, font=("Arial", 14))        # Input field for the OTP
        otp_entry.pack(pady=10)

        submit_button = tk.Button(otp_window, text="Submit", command=otp_window.quit)       # Submit button triggers .quit() on the popup — breaks mainloop() and continues flow
        submit_button.pack(pady=10)

# Display a countdown timer in red to alert the user about the remaining time
        countdown_label = tk.Label(otp_window, text=f"Time remaining: {self.time_limit} seconds", fg="red")
        countdown_label.pack(pady=10)

        def update_countdown():
            for i in range(self.time_limit, 0, -1):
                countdown_label.config(text=f"Time remaining: {i} seconds")     # Dynamically update the label with the remaining time
                otp_window.update()     # Force UI update so the label refreshes in real-time
                time.sleep(1)
            otp_window.destroy()

        threading.Thread(target=update_countdown).start()       # Run the countdown function in a separate thread so it doesn't block the mainloop/UI

        otp_window.mainloop()       # Start the event loop to display the popup window and wait for user interaction
        otp = otp_entry.get().strip()       # Once the user submits or the countdown ends, retrieve the entered OTP also here, .strip() ensures whitespace is removed
        otp_window.destroy()
        return otp

# A.I Generated
#Iterations
class FileEncryptor:        # Class that Handles file encryption
    CHUNK_SIZE = 1024 * 1024  # 1MB chunks

    @staticmethod
    def ask_iterations(root, action):
        response = messagebox.askyesno("Multiple Iterations", 
                                     f"Do you want to {action} multiple times?")
        if not response:        # If user selects 'No', return 1 (default to single iteration)
            return 1
        
            # Create a new popup window to collect number of iterations
        popup = tk.Toplevel(root)
        popup.title("Iteration Count")
        popup.geometry("300x150")
        
        tk.Label(popup, text=f"How many times to {action}?").pack(pady=10)      # Label prompting user to input the number of times to run the action
        
          # Entry field for the user to enter an integer value
        entry = tk.Entry(popup)
        entry.pack(pady=10)
        entry.insert(0, "1")# Pre-fill with default value "1"

        
        result = [1]
        
        def submit():
            try:
                val = int(entry.get())      # Convert user input to an integer
                if val < 1:
                    raise ValueError        # Enforce that value must be a positive integer
                result[0] = val      # Store the validated input into the result list
                popup.destroy()     # Close the popup window if everything is fine
            except ValueError:
                messagebox.showerror("Error", "Please enter a positive integer")         # Show an error popup if input is not a valid positive integer
        
        tk.Button(popup, text="Submit", command=submit).pack(pady=10)       # Adds a 'Submit' button to the popup and binds it to the `submit` function
        popup.grab_set()        # Prevents user from interacting with other windows until this popup is closed
        popup.wait_window()     # Blocks execution until the popup window is destroyed
        return result[0]

    @staticmethod
    def encrypt_file(file_path, key, root):     #Function that helps in encryption
        iterations = FileEncryptor.ask_iterations(root, "encrypt")       # Ask user how many times to repeat the encryption process
        temp_files = []
        
        try:
            output_file = file_path + '.enc'
            if os.path.exists(output_file):      # If encrypted file already exists, prompt user for permission to overwrite
                if not messagebox.askyesno("Overwrite?", "Encrypted file already exists. Overwrite?"):
                    return
            
            for i in range(iterations):
                progress_window = tk.Toplevel(root)
                progress_window.title(f"Encryption Progress (Iteration {i+1}/{iterations})")
                progress_window.geometry("350x150")

                progress_label = tk.Label(progress_window, 
                                       text=f"Encrypting (Iteration {i+1}/{iterations})...")
                progress_label.pack(pady=10)

                progress_bar = ttk.Progressbar(progress_window, 
                                            orient="horizontal", 
                                            length=200, 
                                            mode="determinate")
                progress_bar.pack(pady=10)

                input_file = file_path if i == 0 else temp_files[-1]        # Dynamically determine input and output file paths for each encryption round
                output_file = f"{file_path}.temp.{i}" if i < iterations-1 else f"{file_path}.enc"        # Temp files used for intermediate iterations; final iteration writes to .enc

# Generate a random Initialization Vector (IV) and set up AES encryption in CBC mode
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                encryptor = cipher.encryptor()

                with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                    outfile.write(iv)
                    total_size = os.path.getsize(input_file)
                    processed_size = 0

                    while True:
                        chunk = infile.read(FileEncryptor.CHUNK_SIZE)
                        if not chunk:
                            break
                        if len(chunk) % 16 != 0:         # Pad the chunk manually if it's not aligned to AES block size (16 bytes)
                            chunk += b' ' * (16 - len(chunk) % 16)
                        encrypted_chunk = encryptor.update(chunk)
                        outfile.write(encrypted_chunk)

                        processed_size += len(chunk)
                        progress = (processed_size / total_size) * 100        # Update GUI progress bar to reflect percentage completion
                        progress_bar['value'] = progress
                        progress_window.update()

                    outfile.write(encryptor.finalize())

                if i < iterations-1:         # Save intermediate encrypted files for multi-pass encryption
                    temp_files.append(output_file)

                progress_window.destroy()
            
            for temp_file in temp_files:         # Clean up temporary intermediate encrypted files after final encryption
                os.remove(temp_file)

            messagebox.showinfo("Success", 
                              f"File encrypted {iterations} times and saved as {file_path}.enc")
            
        except Exception as e:
            for temp_file in temp_files:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            if 'progress_window' in locals():
                progress_window.destroy()
            messagebox.showerror("Error", f"Encryption failed: {e}")

# A.I Generated
    @staticmethod
    def decrypt_file(file_path, key, root):     # Function that Handles file edecryption
        iterations = FileEncryptor.ask_iterations(root, "decrypt")
        temp_files = []
        
        try:
            if not file_path.endswith('.enc'):      # If the file doesn’t have .enc extension, warn the user. Allow override for advanced use cases.
                if not messagebox.askyesno("Warning", "File doesn't have .enc extension. Continue anyway?"):
                    return
            
            output_file = file_path.replace('.enc', '')      # Determine output filename and confirm overwrite if target already exists
            if os.path.exists(output_file):
                if not messagebox.askyesno("Overwrite?", "Decrypted file already exists. Overwrite?"):
                    return
            
            for i in range(iterations):
                progress_window = tk.Toplevel(root)
                progress_window.title(f"Decryption Progress (Iteration {i+1}/{iterations})")
                progress_window.geometry("350x150")

                progress_label = tk.Label(progress_window, 
                                       text=f"Decrypting (Iteration {i+1}/{iterations})...")
                progress_label.pack(pady=10)

                progress_bar = ttk.Progressbar(progress_window, 
                                            orient="horizontal", 
                                            length=200, 
                                            mode="determinate")
                progress_bar.pack(pady=10)

                input_file = file_path if i == 0 else temp_files[-1]          # Handle input/output file paths for each decryption iteration — temporary files for multi-pass
                output_file = f"{file_path}.temp.{i}" if i < iterations-1 else file_path.replace('.enc', '')

                with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                    iv = infile.read(16)          # Read the IV stored at the beginning of the encrypted file and initialize AES-CBC decryption
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                    decryptor = cipher.decryptor()

                    total_size = os.path.getsize(input_file)
                    processed_size = 0

                    while True:
                        chunk = infile.read(FileEncryptor.CHUNK_SIZE)
                        if not chunk:
                            break
                        decrypted_chunk = decryptor.update(chunk)
                        outfile.write(decrypted_chunk)

                        processed_size += len(chunk)    
                        progress = (processed_size / total_size) * 100       # Real-time GUI progress bar update based on how much of the file has been processed

                        progress_bar['value'] = progress
                        progress_window.update()

                    outfile.write(decryptor.finalize())

                if i < iterations-1:         # Real-time GUI progress bar update based on how much of the file has been processed

                    temp_files.append(output_file)

                progress_window.destroy()
            
            for temp_file in temp_files:         # Cleanup temporary files used in multi-pass decryption
                os.remove(temp_file)

            messagebox.showinfo("Success", 
                              f"File decrypted {iterations} times and saved as {file_path.replace('.enc', '')}")
            
        except Exception as e:
            for temp_file in temp_files:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            if 'progress_window' in locals():         # Handle exceptions gracefully and ensure GUI elements are closed even on failure
                progress_window.destroy()
            messagebox.showerror("Error", f"Decryption failed: {e}")

class OTPNotifier:      # Class that Sends OTPs via SMS  
    @staticmethod
    def generate_random_otp():
        return random.randint(100000, 999999)

    @staticmethod
    def send_otp(phone_number):      # Call internal method to generate the OTP to send
        otp = OTPNotifier.generate_random_otp()
        messaging_client = MessagingClient(TELESIGN_CUSTOMER_ID, TELESIGN_API_KEY)      # Initialize the Telesign client with environment credentials for sending the message
        message = f"Your OTP code is {otp}"
        response = messaging_client.message(phone_number, message, message_type='ARN')      # Send the message using Telesign's Messaging API; 'ARN' indicates Alert/Reminder/Notification message type

        if response.status_code == 200:       # Check if the API call was successful, and log results or errors accordingly
            print("OTP sent successfully!")
            return otp
        else:
            print(f"Failed to send OTP. Status Code: {response.status_code}")
            print(f"Response: {response.content}")
            return None

    @staticmethod
    def verify_phone_otp(sent_otp, root):
        attempts = 0        #No. of attempts left
        retry_limit = 3     #Total retry limit
        time_limit = 30     #Timeleft to enter the otp 

        otp_manager = OTPManager()

        while attempts < retry_limit:
            otp = otp_manager.get_phone_otp_from_gui(root)
            if otp is None: #If OTP entry is missed due to the timeout, exit the program immediately.
                print("Time limit exceeded. Exiting.")
                logging.warning("Phone OTP verification failed: Time limit exceeded.")
                sys.exit(1)

            if otp == str(sent_otp):    #Casting        #Converts the integer OTP sent to string for comparison with user input.
                print("Phone OTP verification successful!")
                logging.info("Phone OTP verification successful.")
                return True
            else:
                attempts += 1
                print(f"Invalid phone OTP. Attempts remaining: {retry_limit - attempts}")
                logging.warning(f"Phone OTP verification failed: Attempt {attempts}.")      #Lets the user know how many retries are left.

        print("Maximum OTP attempts reached. Exiting.")
        logging.warning("Phone OTP verification failed: Maximum attempts reached.")
        sys.exit(1)

#GUI 
class FileSelector:
    @staticmethod
    def select_file():       
        file_path = filedialog.askopenfilename()        # File Handling
        if file_path:
            return file_path
        else:
            messagebox.showerror("!!Error!!", "No file selected!")
            return None

    @staticmethod
    def show_action_popup():
        action = messagebox.askquestion("Encrypt or Decrypt?", "Would you like to Encrypt? (Yes) or Decrypt? (No)")
        if action == 'yes':
            return 'encrypt'
        elif action == 'no':
            return 'decrypt'
        else:
            print("Invalid option. Exiting.")
            return None
            
#A.I. Generated
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget    
        self.text = text        # The tooltip text that will appear on hover
        self.tooltip = None     # Placeholder for the tooltip window
        self.widget.bind("<Enter>", self.show_tooltip)      # When the mouse enters the widget area, show tooltip
        self.widget.bind("<Leave>", self.hide_tooltip)      # When the mouse enters the widget area, hide it

#A.I. Generated
    def show_tooltip(self, event):
        x, y, _, _ = self.widget.bbox("insert")     # Get the bounding box coordinates of the insertion cursor in the widget
        x += self.widget.winfo_rootx() + 25     # Offset x by root window position + 25 pixels for spacing
        y += self.widget.winfo_rooty() + 25     # Offset x by root window position + 25 pixels for spacing

        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)      # Remove window decoration
        self.tooltip.wm_geometry(f"+{x}+{y}")       # Set the absolute screen position of the tooltip window

    # Create and place the label with tooltip text
        label = tk.Label(self.tooltip, text=self.text, background="yellow", relief="solid", borderwidth=1)
        label.pack()

    def hide_tooltip(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

#A.I. Generated
def show_help():
    help_window = tk.Toplevel()     # Create a new popup window as a child of the main Tkinter window
    help_window.title("Help")
    help_window.geometry("400x300")     #Dimensions

 # Static multiline string containing instructions for users
    help_text = """     
    Instructions:
    1. Enter your OTP from Google/Microsoft Authenticator.
    2. Select a file to encrypt or decrypt.
    3. Choose if you want multiple iterations.
    4. Follow the on-screen instructions.
    """
    help_label = tk.Label(help_window, text=help_text, justify="left")      # Display instructions left-aligned inside a Label widget
    help_label.pack(pady=20)        # Add the label to the window with vertical padding

def show_operation_menu(root, key):

    menu_window = tk.Toplevel(root)     # Create a new popup window as a child of the main Tkinter window
    menu_window.title("Continue or Exit")
    menu_window.geometry("300x200")     #Dimensions
    
    label = tk.Label(menu_window, text="Would you like to perform another operation?")
    label.pack(pady=20)     # Add the label to the window with vertical padding
    
    def encrypt():
        menu_window.destroy()
        file_path = FileSelector.select_file()
        if file_path:
            FileEncryptor.encrypt_file(file_path, key, root)
            show_operation_menu(root, key)
    
    def decrypt():
        menu_window.destroy()
        file_path = FileSelector.select_file()
        if file_path:
            FileEncryptor.decrypt_file(file_path, key, root)
            show_operation_menu(root, key)
    
    encrypt_btn = tk.Button(menu_window, text="Encrypt Another File", command=encrypt)
    encrypt_btn.pack(pady=5)
    
    decrypt_btn = tk.Button(menu_window, text="Decrypt Another File", command=decrypt)
    decrypt_btn.pack(pady=5)
    
    exit_btn = tk.Button(menu_window, text="Exit", command=root.quit)
    exit_btn.pack(pady=5)
    

    menu_window.protocol("WM_DELETE_WINDOW", menu_window.destroy)

def main():
        
    root = tk.Tk()
    root.title("Secure File Encryption Tool")
    root.geometry("150x100")

    help_button = tk.Button(root, text="Help", command=show_help)
    help_button.pack(pady=10)

    EnvironmentManager.prompt_for_env_vars()

    otp_manager = OTPManager()
    secret = otp_manager.secret

    phone_authenticated = False
    if PHONE_NUMBER:
        sent_otp = OTPNotifier.send_otp(PHONE_NUMBER)
        if sent_otp:
            phone_authenticated = OTPNotifier.verify_phone_otp(sent_otp, root)
        else:
            messagebox.showerror("Error", "Failed to send OTP. Continuing with TOTP only.")
    else:
        print("No phone number provided for OTP. Continuing with TOTP only.")

    # Always require TOTP authentication
    if not otp_manager.authenticate_user(root):
        messagebox.showerror("Error", "Authentication failed. Exiting.")
        sys.exit(1)

    key = secret.encode('utf-8')[:32]
    
    # Initial operation selection
    def select_operation():
        operation = FileSelector.show_action_popup()
        if operation == 'encrypt':
            file_path = FileSelector.select_file()
            if file_path:
                FileEncryptor.encrypt_file(file_path, key, root)
                show_operation_menu(root, key)
        elif operation == 'decrypt':
            file_path = FileSelector.select_file()
            if file_path:
                FileEncryptor.decrypt_file(file_path, key, root)
                show_operation_menu(root, key)
        else:
            root.quit()
    
    select_operation()
    root.mainloop()

if __name__ == "__main__":
    main()
