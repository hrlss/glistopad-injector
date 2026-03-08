#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE
#undef _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>

void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void PrintBanner() {
    SetColor(11);
    std::cout << "\n";
    std::cout << " ________.__  .__          __                              .___\n";
    std::cout << "/  _____/|  | |__| _______/  |_  ____ ______  ____     __| _/\n";
    std::cout << "/   \\  ___|  | |  |/  ___/\\   __\\/  _ \\\\____ \\/    \\  / __ | \n";
    std::cout << "\\    \\_\\  \\  |_|  |\\___ \\  |  | (  <_> )  |_> >   |  \\/ /_/ |\n";
    std::cout << " \\______  /____/__/____  > |__|  \\____/|   __/|___|  /\\____ |\n";
    std::cout << "        \\/             \\/              |__|         \\/      \\/\n";
    SetColor(8);
    std::cout << "        glistopad dll injector  by hrlss & glistopad.lol\n";
    SetColor(9);
    std::cout << "        github.com/hrlss\n\n";
    SetColor(7);
}

void Log(const char* level, const std::string& msg, WORD color) {
    SetColor(8);  std::cout << "[";
    SetColor(color); std::cout << level;
    SetColor(8);  std::cout << "] ";
    SetColor(7);  std::cout << msg << "\n";
}

void LogOK(const std::string& m) { Log(" OK ", m, 10); }
void LogFail(const std::string& m) { Log("FAIL", m, 12); }
void LogInfo(const std::string& m) { Log("INFO", m, 11); }
void LogWarn(const std::string& m) { Log("WARN", m, 14); }

std::string LastErrorStr() {
    DWORD err = GetLastError();
    char buf[512] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, 0, buf, sizeof(buf), NULL);
    int len = (int)strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) buf[--len] = 0;
    std::ostringstream oss;
    oss << buf << " (code " << err << ")";
    return oss.str();
}

std::string StrToLower(std::string s) {
    for (size_t i = 0; i < s.size(); ++i)
        s[i] = (char)tolower((unsigned char)s[i]);
    return s;
}

void StrTrim(std::string& s) {
    while (!s.empty() && (s[0] == ' ' || s[0] == '\t')) s.erase(s.begin());
    while (!s.empty() && (s[s.size() - 1] == ' ' || s[s.size() - 1] == '\t' ||
        s[s.size() - 1] == '\r' || s[s.size() - 1] == '\n'))
        s.resize(s.size() - 1);
}

std::string PathGetFilename(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

std::string PathGetDir(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? std::string(".") : path.substr(0, pos);
}

struct ProcEntry { DWORD pid; std::string name; };

std::vector<ProcEntry> FindProcessesByName(const std::string& procName) {
    std::vector<ProcEntry> results;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return results;

    PROCESSENTRY32 pe32;
    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snap, &pe32)) {
        do {
            std::string name(pe32.szExeFile);
            if (StrToLower(name) == StrToLower(procName)) {
                ProcEntry e; e.pid = pe32.th32ProcessID; e.name = name;
                results.push_back(e);
            }
        } while (Process32Next(snap, &pe32));
    }
    CloseHandle(snap);
    return results;
}

bool IsDllLoaded(DWORD pid, const std::string& dllName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32 me32;
    ZeroMemory(&me32, sizeof(me32));
    me32.dwSize = sizeof(MODULEENTRY32);

    std::string target = StrToLower(dllName);
    bool found = false;
    if (Module32First(snap, &me32)) {
        do {
            if (StrToLower(std::string(me32.szModule)) == target) { found = true; break; }
        } while (Module32Next(snap, &me32));
    }
    CloseHandle(snap);
    return found;
}

bool InjectDLL(DWORD pid, const std::string& dllFullPath) {
    LogInfo("Opening process PID " + std::to_string(pid) + " ...");
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) { LogFail("OpenProcess failed: " + LastErrorStr()); return false; }
    LogOK("Process handle acquired.");

    SIZE_T pathLen = dllFullPath.size() + 1;
    LPVOID pMem = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) { LogFail("VirtualAllocEx failed: " + LastErrorStr()); CloseHandle(hProcess); return false; }

    if (!WriteProcessMemory(hProcess, pMem, dllFullPath.c_str(), pathLen, NULL)) {
        LogFail("WriteProcessMemory failed: " + LastErrorStr());
        VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    LogOK("DLL path written to remote memory.");

    LPVOID pLoadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLib) {
        LogFail("GetProcAddress failed: " + LastErrorStr());
        VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LogInfo("Creating remote thread -> LoadLibraryA ...");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLib, pMem, 0, NULL);
    if (!hThread) {
        LogFail("CreateRemoteThread failed: " + LastErrorStr());
        VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 8000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (exitCode == 0) { LogFail("LoadLibrary returned NULL (wrong path or bitness)."); return false; }

    std::ostringstream oss; oss << std::hex << exitCode;
    LogOK("Injection successful! Module handle: 0x" + oss.str());
    return true;
}

std::string AutoFindDll(const std::string& dir) {
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((dir + "\\*.dll").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return "";
    std::string result = dir + "\\" + fd.cFileName;
    FindClose(h);
    return result;
}

void ReadConfig(const std::string& cfgPath, std::string& proc, std::string& dll) {
    std::ifstream f(cfgPath.c_str());
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        size_t cmt = line.find(';');
        if (cmt != std::string::npos) line = line.substr(0, cmt);
        StrTrim(line);
        if (line.empty()) continue;
        if (line.substr(0, 8) == "process=") { proc = line.substr(8); StrTrim(proc); }
        else if (line.substr(0, 4) == "dll=") { dll = line.substr(4); StrTrim(dll); }
    }
}

int main(int argc, char* argv[]) {
    PrintBanner();

    char exeBuf[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exeBuf, MAX_PATH);
    std::string exeDir = PathGetDir(std::string(exeBuf));

    std::string targetProcess = "";
    std::string dllPath = "";

    std::string cfgPath = exeDir + "\\config.ini";
    {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(cfgPath.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            FindClose(h);
            LogInfo("Found config.ini");
            ReadConfig(cfgPath, targetProcess, dllPath);
        }
    }

    if (argc >= 2) targetProcess = argv[1];
    if (argc >= 3) dllPath = argv[2];

    if (dllPath.empty()) {
        dllPath = AutoFindDll(exeDir);
        if (!dllPath.empty()) LogInfo("Auto-detected DLL: " + dllPath);
    }

    if (!dllPath.empty() &&
        dllPath.find('\\') == std::string::npos &&
        dllPath.find('/') == std::string::npos) {
        dllPath = exeDir + "\\" + dllPath;
    }

    if (targetProcess.empty()) {
        LogFail("No target process specified.");
        std::cout << "\n  Usage:  injector.exe <target.exe> [payload.dll]\n\n";
        std::cout << "  config.ini example:\n";
        std::cout << "    process=target.exe\n    dll=payload.dll\n\n";
        std::cout << "Press Enter..."; std::cin.get(); return 1;
    }
    {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(dllPath.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            LogFail("DLL not found: " + (dllPath.empty() ? "(none)" : dllPath));
            std::cout << "Press Enter..."; std::cin.get(); return 1;
        }
        FindClose(h);
    }

    LogInfo("Target : " + targetProcess);
    LogInfo("DLL    : " + dllPath);
    std::cout << "\n";

    std::vector<ProcEntry> procs = FindProcessesByName(targetProcess);
    if (procs.empty()) {
        LogFail("Process \"" + targetProcess + "\" not found.");
        std::cout << "Press Enter..."; std::cin.get(); return 1;
    }
    LogInfo("Found " + std::to_string((int)procs.size()) + " instance(s)");

    std::string dllFileName = PathGetFilename(dllPath);
    int injected = 0, skipped = 0;

    for (size_t i = 0; i < procs.size(); ++i) {
        std::cout << "\n";
        LogInfo("-- PID " + std::to_string(procs[i].pid) + " --");
        if (IsDllLoaded(procs[i].pid, dllFileName)) {
            LogWarn("Already loaded, skipping.");
            ++skipped; continue;
        }
        if (InjectDLL(procs[i].pid, dllPath)) ++injected;
    }

    std::cout << "\n";
    SetColor(11);
    std::cout << "  Done: " << injected << " injected, "
        << skipped << " skipped, "
        << ((int)procs.size() - injected - skipped) << " failed\n\n";
    SetColor(7);
    std::cout << "Press Enter..."; std::cin.get();
    return (injected > 0) ? 0 : 1;
}
