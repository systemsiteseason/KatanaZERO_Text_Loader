#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <TlHelp32.h>
#include <tchar.h>
#include <string>
#include <comutil.h>

using namespace std;

std::vector<std::string> ptrText;
std::vector<DWORD> ptr;
uintptr_t clientBase;
DWORD pID = GetCurrentProcessId();
HANDLE hHandle;
DWORD jmpBack;
DWORD baseAdds;
DWORD offsetInput;

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

bool Hook(void* toHook, void* ourFunct, int len) {
    if (len < 5) {
        return false;
    }

    DWORD curProtection;
    VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);

    memset(toHook, 0x90, len);

    DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5;

    *(BYTE*)toHook = 0xE9;
    *(DWORD*)((DWORD)toHook + 1) = relativeAddress;

    DWORD temp;
    VirtualProtect(toHook, len, curProtection, &temp);

    return true;
}

void CompareData(DWORD input) noexcept {
    std::vector<DWORD>::iterator it = std::find(ptr.begin(), ptr.end(), input - clientBase);
    if (it != ptr.end()) {
        int index = std::distance(ptr.begin(), it);
        if (ptrText[index].size() > 0x0F)
            ReadProcessMemory(hHandle, (BYTE*)&ptrText[index] + 0x4, &baseAdds, sizeof(baseAdds), NULL);
        else
            baseAdds = (DWORD)&ptrText[index];
    }
    else
        baseAdds = input;
}

void tokenize(std::string const& str, const char delim,
    std::vector<std::string>& out)
{
    size_t start;
    size_t end = 0;

    while ((start = str.find_first_not_of(delim, end)) != std::string::npos)
    {
        end = str.find(delim, start);
        out.push_back(str.substr(start, end - start));
    }
}

void __declspec(naked) inputText() {
    _asm {
        mov esi, ecx
        mov edi, [ebp + 8]
        mov offsetInput, edi
    }
    CompareData(offsetInput);
    _asm {
        mov edi, baseAdds
        jmp[jmpBack]
    }
}

DWORD WINAPI MainThread(LPVOID param) {
    std::ifstream loadsub("subtitle.txt");
    std::string str;
    while (std::getline(loadsub, str))
    {
        std::vector<std::string> out;
        tokenize(str, '=', out);
        DWORD key = std::strtoul(out[0].c_str(), NULL, 16);
        std::string value = out[1];
        ptr.push_back(key);
        ptrText.push_back(value);
    }

    hHandle = GetCurrentProcess();
    int hookLength = 5;
    clientBase = GetModuleBaseAddress(pID, L"Katana ZERO.exe");
    DWORD hookAddr = clientBase + 0x5D6458;
    jmpBack = hookAddr + hookLength;
    Hook((void*)hookAddr, inputText, hookLength);

    while (true) {
        if (GetAsyncKeyState(VK_ESCAPE)) break;
        Sleep(50);
    }

    FreeLibraryAndExitThread((HMODULE)param, 0);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, MainThread, hModule, 0, 0);
        break;
    }
    return TRUE;
}