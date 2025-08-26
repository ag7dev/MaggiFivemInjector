#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <vector>

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


DWORD getprocessbyname(const char* name) {
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        log_error("CreateToolhelp32Snapshot failed.", true);
        return 0; // Return 0 on failure
    }

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

int main() {
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(hconsole, &mode)) {
        SetConsoleMode(hconsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    SetConsoleTitleA("Maggi Fivem Injector");
    print_banner();

    log_info("Waiting for FiveM.exe...");

    DWORD pid = 0;
    while (!pid) {
        pid = getprocessbyname("FiveM.exe");
        if (!pid) {
            log_waiting("FiveM.exe not found, retrying...");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    // Clear the "retrying" line
    std::cout << std::endl;
    log_success("FiveM found! PID: " + std::to_string(pid));

    char dllpath[MAX_PATH];
    if (GetFullPathNameA("region.dll", MAX_PATH, dllpath, nullptr) == 0) {
        log_error("Couldn't find region.dll. Make sure it's in the same directory.", true);
        system("pause");
        return -1;
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
    log_success("region.dll injected into FiveM! Have fun!");
    log_info("You can close this window now.");
    std::cout << "------------------------------------------------------------------" << std::endl;


    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(hprocess, mem, 0, MEM_RELEASE);
    CloseHandle(hprocess);

    std::this_thread::sleep_for(std::chrono::seconds(5));

    return 0;
}
