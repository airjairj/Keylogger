# Keylogger

A simple, open-source keylogger tool for Windows, written in C++ and Python.  
This project demonstrates system-wide keylogging, secure communication, and basic exfiltration techniques for educational and research purposes.

---

## Features

- **System-wide keylogging** using a low-level keyboard hook (DLL).
- **Modular architecture:** EXE loads the DLL and handles networking.
- **Secure communication:** Diffie-Hellman key exchange and AES encryption.
- **Stealth mode + Persistance** Invisible mode is available to have the program run without opening windows or showing up on the taskbar (Persistance is a WIP)
- **Python server:** Receives, decrypts, and logs keystrokes; can forward logs to Telegram.

---

## Requirements

- **Windows:** Tested on Windows 10/11
- **C++ Compiler:** MinGW-w64 recommended
- **OpenSSL:** For AES/Diffie-Hellman (install and add to your compiler's include/lib paths)
- **Python 3.8+** (for server)
  - `pip install pycryptodome python-telegram-bot`

---

## Usage

1. **Start the Python server** to listen for incoming logs.
2. **Run the keylogger executable** (keylogger.exe) on the target machine (keyhook.dll is required in the same folder).
3. **Stop the keylogger** by closing the console window or pressing `Ctrl+C` in the terminal.

---

## Disclaimer

This project is for educational and research purposes only.  
Use responsibly and ensure you have permission to test keylogging on any device.  
The authors are not responsible for any misuse or damage caused by this software.

---

## References

- [Microsoft Docs: Keyboard Input](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Python Documentation](https://docs.python.org/3/)
- [pycryptodome Documentation](https://www.pycryptodome.org/src/introduction)
- [python-telegram-bot Documentation](https://python-telegram-bot.readthedocs.io/en/stable/)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
