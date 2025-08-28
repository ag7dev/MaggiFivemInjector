#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <cwchar>
#include <shellapi.h>

// --- Design Improvements ---
#define RESET   "\x1b[0m"
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"

void print_banner() {
    std::cout << MAGENTA << R"(
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⣤⠀⠀⠀⠀⠀⠀⣠⣤⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⣿⠀⠀⣤⣶⣷⣶⣿⠁⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⢸⣆⣼⡏⢠⣦⡈⢿⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⠀⠘⠛⢻⣧⡈⠛⣀⣿⡀⣸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠏⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⡏⠀⠈⣷⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣀⣀⠀⠀⠀⠀⠀⣀⡤⠶⣿⣿⠿⠤⣤⣴⣿⠀⠀⠀⢀⡀⠀⠀⠄⠀⠀⠀⠀⠀⠀⣀⣴⣶⣿⣷⣶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠸⣿⠙⠻⣿⣿⣷⣶⣿⠥⡄⠀⠀⠀⠀⠀⠀⠈⠙⢷⡶⠆⠘⠟⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⠟⠉⠀⠈⠙⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠹⣧⠘⠟⠙⣿⠁⠀⠀⠐⢀⡀⢤⡀⢤⡀⢢⡘⢦⡄⠀⠀⠀⢰⡂⠀⠀⠀⠀⠀⢸⣿⡏⠀⠀⠀⠀⠀⠈⠻⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢽⣷⠆⢀⡿⠀⠀⠀⣶⠀⠹⡌⣷⠀⣿⣄⣿⡈⣿⡶⢳⡤⢸⣧⠀⠀⠀⠀⠀⢸⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢰⣶⡄⠿⠠⣇⢸⡄⣿⡀⠀⢻⣿⡶⢿⣌⣻⣇⣿⣿⢈⡇⢸⣏⠳⣄⠀⠀⠀⠀⢿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣀⡀⠋⠁⢀⣼⢿⡎⣷⣘⣧⠀⠀⠙⠸⣾⡟⠛⣿⠃⢸⢿⣇⠘⣿⠳⣬⣟⣶⣤⠀⠈⠻⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠉⠳⣾⣀⣼⠿⣌⣷⣼⣧⣽⡆⠀⠀⠀⠈⠁⠀⢉⣀⡜⣸⡏⠀⣿⡆⠀⠈⠁⠀⠀⠀⠀⠈⠙⢿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣾⠋⣽⡄⣿⠛⡃⡀⠙⠃⠀⣠⣶⣦⠀⢠⡿⠏⢀⣿⣀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣴⣾⣄⣿⣧⡹⣆⠀⠸⣧⣀⣀⣈⣛⣃⡴⠟⠁⣠⣿⣿⡏⣰⣿⡀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣠⣾⠟⢁⠀⠀⠉⢷⡙⣦⡀⠀⠈⠉⠉⠉⠉⠶⠤⠞⢻⣿⣿⣷⣿⣿⡇⠀⠀⣀⣀⣀⠀⠀⠀⠀⣠⣾⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⣇⠀⡏⣰⢂⣀⠠⡟⠺⢇⣰⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⠘⢿⣿⣿⣿⣿⣿⣶⣾⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⠓⠛⠈⠛⠉⠀⠘⠆⢸⣿⡇⠀⠀⠀⠀⠀⠀⠲⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⡿⣿⣿⣿⣿⣿⣷⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⠀⠀⠀⢀⣠⣾⣿⣿⣄⠀⠀⠀⠀⠀⠀⠘⢻⣿⣿⣿⣿⠏⠀⠀⠛⠀⠙⠻⣿⣿⣿⣿⣿⣿⣿⣶⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⡿⣿⣦⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⡇⠀⡰⠃⠀⠀⠈⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠛⢻⣿⣿⣿⡇⠈⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⣰⡋⠀⢸⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⡀⠀⣼⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⠁⠀⠸⠟⠻⠿⠇⠀⠀⠀⠀⢀⡴⠃⢀⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡛⠣⣀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠋⠀⣠⣾⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⣷⣦⣭⣀⣀⣀⡀⣸⣃⣀⣠⣴⣶⣶⣿⣿⣿⣿⣯⣀⣀⠀⠀⣠⣾⣷⣤⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠌⠉⠉⠁⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣄⠀
⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⡫⠀⠴⠚⡠⠤⠤⠤⣾⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⢿⣿⡿⠿⠿⠿⠿⢿⣿⠿⠿⠿⡿⠟⠛⠀
⠀⠀⣰⡾⠿⡟⠻⣷⣿⢻⣷⣀⣀⣀⣀⢀⣉⡀⣀⣉⠀⠀⢀⣀⣀⣉⣀⣀⡀⣀⣀⣀⡀⠀⢀⣼⡟⢻⡷⠀⠀⢀⣴⠿⢿⡿⣿⠟⠿⣦⡀
⠀⠀⣿⣅⠘⠿⣷⣿⡉⠀⣙⣿⣉⣉⠻⣟⠛⣿⡟⢙⣿⠀⣿⠋⢉⠙⢋⠙⢻⣿⣉⡉⠻⣿⠟⠋⠁⢸⡇⠀⣴⡿⢃⣴⡿⣿⡿⠿⢀⣿⠇
⠀⠀⣸⡿⢷⡦⠈⣿⡇⠈⢿⡟⠉⣥⠀⢹⣆⠘⠀⣾⠇⠀⣿⠀⢸⠂⢸⡇⢸⡟⢉⣅⠀⣇⠀⢿⠇⢸⡇⠀⢻⣧⡈⢿⣶⣿⣷⡶⠈⣿⠀
⠀⠀⠻⣷⣤⣤⣾⠟⢿⣦⣴⣷⣦⣤⣤⣾⡿⠀⣼⡏⠀⠀⢿⣦⣾⣦⣾⣧⣼⣷⣤⣤⣤⣿⣷⣤⣤⣼⡏⠀⠀⠙⢷⣤⣽⣷⣤⣤⣾⠟⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢷⣶⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
)" << RESET << std::endl;
    std::cout << "              Injector by Maggi " << std::endl;
    std::cout << "------------------------------------------------------------------" << std::endl;
}

void log_info(const std::string& msg) {
    std::cout << BLUE << "[INFO] " << RESET << msg << std::endl;
}

void log_waiting(const std::string& msg) {
    std::cout << YELLOW << "[WAIT] " << RESET << msg << "\r";
    std::cout.flush();
}

void log_success(const std::string& msg) {
    std::cout << GREEN << "[SUCCESS] " << RESET << msg << std::endl;
}

void log_error(const std::string& msg, bool print_last_error = false) {
    std::cerr << RED << "[ERROR] " << RESET << msg;
    if (print_last_error) {
        std::cerr << " | Win32 Error Code: " << GetLastError();
    }
    std::cerr << std::endl;
}
// --- End of Design Improvements ---

bool is_run_as_admin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin;
}


DWORD getprocessbyname(const char* name) {
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        log_error("CreateToolhelp32Snapshot failed.", true);
        return 0; // Return 0 on failure
    }

#ifdef UNICODE
    wchar_t wname[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, MAX_PATH) == 0) {
        CloseHandle(snap);
        return 0;
    }
#endif

    if (Process32First(snap, &entry)) {
        do {
            char procname[MAX_PATH];
            wcstombs_s(nullptr, procname, entry.szExeFile, MAX_PATH);
            if (_stricmp(procname, name) == 0) {
                CloseHandle(snap);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snap, &entry));
    }

    CloseHandle(snap);
    return 0; // Return 0 if not found
}

int main(int argc, char* argv[]) {
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(hconsole, &mode)) {
        SetConsoleMode(hconsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    SetConsoleTitleA("Maggi Fivem Injector");
    print_banner();

    if (!is_run_as_admin()) {
        log_info("Requesting administrator privileges...");
        char path[MAX_PATH];
        if (GetModuleFileNameA(nullptr, path, MAX_PATH)) {
            SHELLEXECUTEINFOA sei{ sizeof(sei) };
            sei.lpVerb = "runas";
            sei.lpFile = path;
            sei.nShow = SW_SHOWNORMAL;
            if (ShellExecuteExA(&sei)) {
                return 0;
            }
        }
        log_error("Failed to obtain administrator privileges.");
        system("pause");
        return -1;
    }

    log_info("Waiting for FiveM...");

    DWORD pid = 0;
    while (!pid) {
        pid = getprocessbyname("FiveM_GTAProcess.exe");
        if (!pid) {
            log_waiting("FiveM not found, retrying...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    // Clear the "retrying" line
    std::cout << std::endl;
    log_success("FiveM found! PID: " + std::to_string(pid));

    if (argc < 2) {
        log_error("Please drag and drop a DLL onto the injector executable.");
        system("pause");
        return -1;
    }

    char dllpath[MAX_PATH];
    if (GetFullPathNameA(argv[1], MAX_PATH, dllpath, nullptr) == 0) {
        log_error("Couldn't resolve DLL path.", true);
        system("pause");
        return -1;
    }
    DWORD attr = GetFileAttributesA(dllpath);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        log_error("Provided DLL path is invalid or not a file.");
        system("pause");
        return -1;
    }

    std::string dll_name = dllpath;
    size_t pos = dll_name.find_last_of("\\/");
    if (pos != std::string::npos) {
        dll_name = dll_name.substr(pos + 1);
    }
    log_info("DLL path resolved to: " + std::string(dllpath));


    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hprocess) {
        log_error("Failed to open process. Try running as administrator.", true);
        system("pause");
        return -1;
    }
    log_success("Successfully opened handle to process.");

    LPVOID mem = VirtualAllocEx(hprocess, nullptr, strlen(dllpath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        log_error("Failed to allocate memory in target process.", true);
        CloseHandle(hprocess);
        system("pause");
        return -1;
    }
    log_success("Memory allocated in target process.");

    if (!WriteProcessMemory(hprocess, mem, dllpath, strlen(dllpath) + 1, nullptr)) {
        log_error("Failed to write DLL path to allocated memory.", true);
        VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        system("pause");
        return -1;
    }
    log_success("Successfully wrote DLL path to memory.");

    HMODULE hkernel = GetModuleHandleA("kernel32.dll");
    if (!hkernel) {
        log_error("Failed to get handle for kernel32.dll.", true);
        VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        system("pause");
        return -1;
    }

    FARPROC loadlib = GetProcAddress(hkernel, "LoadLibraryA");
    if (!loadlib) {
        log_error("Failed to get address of LoadLibraryA.", true);
        VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        system("pause");
        return -1;
    }
    log_success("Successfully found address of LoadLibraryA.");

    HANDLE thread = CreateRemoteThread(hprocess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadlib, mem, 0, nullptr);
    if (!thread) {
        log_error("Failed to create remote thread.", true);
        VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
        CloseHandle(hprocess);
        system("pause");
        return -1;
    }
    log_success("Remote thread created successfully.");

    std::cout << "\n------------------------------------------------------------------" << std::endl;
    log_success(dll_name + " injected into FiveM! Have fun!");
    log_info("You can close this window now.");
    std::cout << "------------------------------------------------------------------" << std::endl;


    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
    CloseHandle(hprocess);

    std::this_thread::sleep_for(std::chrono::seconds(5));

    return 0;
}
