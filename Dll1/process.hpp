#pragma once
#include <string>
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include "lazy.h"

std::uintptr_t process_find(const std::string& name)
{
    const auto snap = LI_FN(CreateToolhelp32Snapshot).safe()(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W proc_entry{};
    proc_entry.dwSize = sizeof proc_entry;

    auto found_process = false;
    if (!!LI_FN(Process32FirstW).safe()(snap, &proc_entry)) {
        do {
            std::wstring wname(name.begin(), name.end());
            if (wcscmp(wname.c_str(), proc_entry.szExeFile) == 0) {
                found_process = true;
                break;
            }
        } while (!!LI_FN(Process32NextW).safe()(snap, &proc_entry));
    }

    LI_FN(CloseHandle).safe()(snap);
    return found_process
        ? proc_entry.th32ProcessID
        : 0;
}
