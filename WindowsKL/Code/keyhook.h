#pragma once

#ifdef KEYHOOK_EXPORTS
#define KEYHOOK_API __declspec(dllexport)
#else
#define KEYHOOK_API __declspec(dllimport)
#endif

extern "C" {
    // Funzione per inizializzare l'hook
    KEYHOOK_API bool StartKeyHook();

    // Funzione per rimuovere l'hook e liberare risorse
    KEYHOOK_API void StopKeyHook();

    // Funzione per ottenere e svuotare il buffer dei tasti catturati
    KEYHOOK_API const char* GetKeyBuffer();
}
