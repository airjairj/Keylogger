import socket

HOST = '127.0.0.1'
PORT = 5000

def main():
    import time
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
                            print(data.decode(errors='ignore'), end='', flush=True)
        except Exception as e:
            print(f"[ERRORE SERVER] {e}. Riavvio tra 2 secondi...")
            time.sleep(2)

if __name__ == "__main__":
    main()