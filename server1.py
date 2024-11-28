import socket
import threading
import os
from tkinter import *
from tkinter import messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

# Master key and AES setup
master_key = input("Set your master key (16/24/32 characters): ").encode('utf-8')
if len(master_key) not in [16, 24, 32]:
    raise ValueError("Key must be 16, 24, or 32 bytes long!")
iv = os.urandom(16)

username = input("Enter your username: ")

def aes_encrypt(plain_text):
    padder = PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def aes_decrypt(cipher_text):
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plain_data = unpadder.update(padded_data) + unpadder.finalize()
    return plain_data.decode()

def setup_server():
    ip_address = ip_entry.get()
    port_number = int(port_entry.get())
    
    global server_socket, client_conn
    server_socket = socket.socket()
    try:
        server_socket.bind((ip_address, port_number))
        server_socket.listen()
        client_conn, client_addr = server_socket.accept()
        setup_window.destroy()
        setup_window.quit()
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to bind or accept connection: {e}")
        error_message.config(text=f"Error: {e}")

def send_message():
    if message_entry.get().strip() != "":
        message_content = message_entry.get()
        encrypted_message = aes_encrypt(message_content)
        client_conn.send(encrypted_message)
        chat_listbox.insert(END, "You: " + message_content)
        save_chat_log(f"Server (You): {message_content} | Encrypted: {encrypted_message.hex()}")
        message_entry.delete(0, END)

def receive_messages():
    while True:
        try:
            encrypted_message = client_conn.recv(1024)
            decrypted_message = aes_decrypt(encrypted_message)
            chat_listbox.insert(END, client_username + ": " + decrypted_message)
            save_chat_log(f"Client ({client_username}): {decrypted_message} | Encrypted: {encrypted_message.hex()}")
        except Exception as e:
            messagebox.showerror("Reception Error", f"Error receiving message: {e}")
            break

def save_chat_log(entry):
    with open("server_chat_log.txt", "a") as log_file:
        log_file.write(entry + "\n")

# Server GUI setup
setup_window = Tk()
setup_window.title("Server Setup")
setup_window.geometry("400x300")
setup_window.resizable(False, False)
setup_window.configure(bg='#1e1e1e')

Label(setup_window, text="Enter IP:", bg='#1e1e1e', fg='#ffffff').pack(fill=X, padx=10, pady=5)
ip_entry = Entry(setup_window, bg='#3a3a3a', fg='#ffffff')
ip_entry.pack(fill=X, padx=10, pady=5)
ip_entry.insert(0, "127.0.0.1")

Label(setup_window, text="Enter Port:", bg='#1e1e1e', fg='#ffffff').pack(fill=X, padx=10, pady=5)
port_entry = Entry(setup_window, bg='#3a3a3a', fg='#ffffff')
port_entry.pack(fill=X, padx=10, pady=5)
port_entry.insert(0, "12345")

Button(setup_window, text="Set IP", command=setup_server, bg='#4caf50', fg="white").pack(padx=10, pady=20)

error_message = Label(setup_window, text="", fg="red", bg='#1e1e1e')
error_message.pack(fill=X, padx=10, pady=5)

setup_window.mainloop()

client_conn.send(username.encode())
client_username = client_conn.recv(1024).decode()

main_window = Tk()
main_window.title(f"Server - {username}")
main_window.geometry("600x500")
main_window.configure(bg='#1e1e1e')

notebook = ttk.Notebook(main_window)
notebook.pack(fill=BOTH, expand=True)

chat_frame = Frame(notebook, bg='#1e1e1e')
notebook.add(chat_frame, text="Chat")

chat_scrollbar = Scrollbar(chat_frame)
chat_scrollbar.pack(side=RIGHT, fill=Y)
chat_listbox = Listbox(chat_frame, yscrollcommand=chat_scrollbar.set, bg='#3a3a3a', fg='#ffffff', selectbackground='#4caf50')
chat_listbox.pack(fill=BOTH, expand=True)
chat_scrollbar.config(command=chat_listbox.yview)

bottom_frame = Frame(chat_frame, bg='#1e1e1e')
bottom_frame.pack(fill=X, side=BOTTOM)

message_entry = Entry(bottom_frame, bg='#3a3a3a', fg='#ffffff')
message_entry.pack(fill=X, side=LEFT, expand=True, padx=5, pady=5)

send_button = Button(bottom_frame, text="Send Message", command=send_message, bg='#4caf50', fg="white")
send_button.pack(side=RIGHT, padx=5, pady=5)

threading.Thread(target=receive_messages).start()
main_window.mainloop()
