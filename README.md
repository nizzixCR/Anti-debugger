C++ Integration Example:

<pre>
std::string GetExecutablePath() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}

std::string GetFileMD5(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "";

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return "";
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    if (!CryptHashData(hHash, (BYTE*)buffer.data(), buffer.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    BYTE hash[16];
    DWORD hashLen = 16;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return ss.str();
}

int main() {
    std::string exePath = GetExecutablePath();
    std::string exeDir = exePath.substr(0, exePath.find_last_of("\\/"));
    std::string dllPath = exeDir + "\\dependencies.dll"; // you can change the name of the dll but you need the dll in the same repertory of the file 
    
    const char* expectedMD5 = "935c369c085d614774e3012865fb09d6"; // file hash of the release x64
    std::string actualMD5 = GetFileMD5(dllPath.c_str());
    if (actualMD5.empty() || actualMD5 != expectedMD5) {
        MessageBoxA(NULL, "DLL verification failed!", "Error", MB_ICONERROR);
        return -1;
    }

    HMODULE hModule = LoadLibraryA(dllPath.c_str());
    if (!hModule) {
        MessageBoxA(NULL, "Failed to load DLL!", "Error", MB_ICONERROR);
        return -1;
    }
} </pre>

C# Integration Example:
<pre>
using System;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LoadLibrary(string dllToLoad);

    static string GetMD5(string filePath)
    {
        using var md5 = MD5.Create();
        using var stream = File.OpenRead(filePath);
        var hash = md5.ComputeHash(stream);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    static void Main()
    {
        string exeDir = AppDomain.CurrentDomain.BaseDirectory;
        string dllPath = Path.Combine(exeDir, "dependencies.dll");
        string expectedHash = "935c369c085d614774e3012865fb09d6";
        string actualHash = GetMD5(dllPath);

        if (actualHash != expectedHash)
        {
            Console.WriteLine("DLL verification failed.");
            return;
        }

        if (LoadLibrary(dllPath) == IntPtr.Zero)
        {
            Console.WriteLine("Failed to load DLL.");
            return;
        }

        Console.WriteLine("DLL loaded successfully.");
    }
}

</pre>

Python Integration Example:
<pre>
  import hashlib
import os
import ctypes

def get_md5(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except FileNotFoundError:
        return None

def main():
    exe_dir = os.path.dirname(os.path.abspath(__file__))
    dll_path = os.path.join(exe_dir, "dependencies.dll")
    expected_md5 = "935c369c085d614774e3012865fb09d6"
    actual_md5 = get_md5(dll_path)

    if actual_md5 != expected_md5:
        ctypes.windll.user32.MessageBoxW(0, "DLL verification failed!", "Error", 0x10)
        return

    try:
        ctypes.cdll.LoadLibrary(dll_path)
        ctypes.windll.user32.MessageBoxW(0, "DLL loaded successfully!", "Success", 0x40)
    except Exception:
        ctypes.windll.user32.MessageBoxW(0, "Failed to load DLL!", "Error", 0x10)

if __name__ == "__main__":
    main()

</pre>
