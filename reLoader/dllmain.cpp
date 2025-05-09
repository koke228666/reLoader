// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>
#include <MinHook.h>
#include <fstream>
#include <string>
#include <cstring>
#include <mutex>
#include <sstream>
#include <map>
#include <vector>

char g_reloaderBasePath[MAX_PATH] = {0};
char g_iniPath[MAX_PATH] = {0};
char g_logPath[MAX_PATH] = {0};
std::mutex g_logMutex;
bool g_clearLogOnStart = false;
bool g_noLog = false;
HMODULE g_hModule = NULL;
std::map<std::string, std::string> g_fileRedirections;

void LogToFile(const std::string& message) {
	if (!g_noLog) {
		std::lock_guard<std::mutex> lock(g_logMutex);
		if (g_logPath[0] == '\0') {
			return;
		}
		std::ofstream logFile(g_logPath, std::ios_base::app);
		if (logFile.is_open()) {
			logFile << message << std::endl;
		}
	}
}

typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
CreateFileA_t nativeCreateFileA = nullptr;


void SetupPathsAndConfig(HMODULE hModuleDLL) { 
    char gameExePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, gameExePath, MAX_PATH); 
    
    std::string gameRootDirStr = gameExePath;
    size_t lastSlashPosExe = gameRootDirStr.find_last_of("\\/");
    if (lastSlashPosExe != std::string::npos) {
        gameRootDirStr = gameRootDirStr.substr(0, lastSlashPosExe + 1); 
    } else {
        strcpy_s(g_reloaderBasePath, MAX_PATH, ".\\"); 
    }
    strncpy_s(g_reloaderBasePath, MAX_PATH, gameRootDirStr.c_str(), _TRUNCATE);

    char dllPath[MAX_PATH] = {0};
    GetModuleFileNameA(hModuleDLL, dllPath, MAX_PATH);
    std::string dllDir = dllPath;
    size_t lastSlashPosDll = dllDir.find_last_of("\\/");
    if (lastSlashPosDll != std::string::npos) {
        dllDir = dllDir.substr(0, lastSlashPosDll + 1);
    } else {
        dllDir = ".\\"; 
    }
    strcpy_s(g_iniPath, MAX_PATH, dllDir.c_str());
    strcat_s(g_iniPath, MAX_PATH, "reLoader.ini");

    strcpy_s(g_logPath, MAX_PATH, dllDir.c_str());
    strcat_s(g_logPath, MAX_PATH, "reLoader.log");

    g_clearLogOnStart = GetPrivateProfileIntA("reLoader", "resetlog", 0, g_iniPath) == 1;
	g_noLog = GetPrivateProfileIntA("reLoader", "nolog", 0, g_iniPath) == 1;

    if (g_clearLogOnStart && !g_noLog) {
        std::ofstream logFile(g_logPath, std::ios_base::trunc); 
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    LogToFile("Config path: " + std::string(g_iniPath));
    
    std::vector<char> sectionBuffer;
    DWORD bufferSize = 2048; // Initial buffer size
    const DWORD MAX_INI_BUFFER_SIZE = 1 * 1024 * 1024; // 1MB max buffer to prevent excessive allocation
    DWORD bytesRead = 0;

    while (true) {
        sectionBuffer.resize(bufferSize);
        bytesRead = GetPrivateProfileSectionA("Redirects", sectionBuffer.data(), bufferSize, g_iniPath);

        if (bytesRead < bufferSize - 2) {
            break; 
        }

        if (bufferSize >= MAX_INI_BUFFER_SIZE) {
            LogToFile("Error: [Redirects] section is too large (exceeds " + std::to_string(MAX_INI_BUFFER_SIZE / 1024) + "KB). Truncating entries.");
            break;
        }
        
        bufferSize *= 2;
        if (bufferSize > MAX_INI_BUFFER_SIZE) {
            bufferSize = MAX_INI_BUFFER_SIZE;
        }
        LogToFile("Info: Increasing buffer for [Redirects] section to " + std::to_string(bufferSize / 1024) + "KB.");
    }

    if (bytesRead > 0) {
        LogToFile("Loading File redirections from [Redirects] section (buffer size used: " + std::to_string(bufferSize / 1024) + "KB):");
        const char* currentEntry = sectionBuffer.data();
        while (*currentEntry) {
			std::string entryStr = currentEntry;

			size_t firstChar = entryStr.find_first_not_of(" \t\n\r\f\v");
			if (firstChar != std::string::npos && entryStr[firstChar] == '#') {
				currentEntry += entryStr.length() + 1;
				continue;
			}

			if (firstChar == std::string::npos) {
				currentEntry += entryStr.length() + 1;
				continue;
			}

            size_t equalsPos = entryStr.find('=');
            if (equalsPos != std::string::npos) {
                std::string fileName = entryStr.substr(0, equalsPos);
				std::string redirPath = entryStr.substr(equalsPos + 1);
				size_t start = fileName.find_first_not_of(" \t\n\r\f\v");
				fileName = (start == std::string::npos) ? "" : fileName.substr(start);
				size_t end = fileName.find_last_not_of(" \t\n\r\f\v");
				fileName = (end == std::string::npos) ? "" : fileName.substr(0, end + 1);

				start = redirPath.find_first_not_of(" \t\n\r\f\v");
				redirPath = (start == std::string::npos) ? "" : redirPath.substr(start);
				end = redirPath.find_last_not_of(" \t\n\r\f\v");
				redirPath = (end == std::string::npos) ? "" : redirPath.substr(0, end + 1);

				if (!fileName.empty() && !redirPath.empty()) {
                    g_fileRedirections[fileName] = redirPath;
                    LogToFile("  Redirecting " + fileName + " to " + redirPath);
                }
            }
            currentEntry += entryStr.length() + 1;
        }
    } else {
        if (sectionBuffer.size() < MAX_INI_BUFFER_SIZE || bytesRead < sectionBuffer.size() -2 ) {
             LogToFile("No redirections found in [Redirects] section or section is empty.");
        }
    }
}


HANDLE WINAPI hooked_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    if (lpFileName) {
        std::string fileNameStr(lpFileName);

        size_t lastSlashPos = fileNameStr.find_last_of("\\/");
        std::string pureFileName = (lastSlashPos == std::string::npos) ? fileNameStr : fileNameStr.substr(lastSlashPos + 1);

        auto it = g_fileRedirections.find(pureFileName);
        if (it != g_fileRedirections.end() && !it->second.empty()) {
            std::string targetFilePath = g_reloaderBasePath;
            std::string relativeRedirectPath = it->second;

            if (!relativeRedirectPath.empty() && (relativeRedirectPath.front() == '\\' || relativeRedirectPath.front() == '/')) {
                relativeRedirectPath = relativeRedirectPath.substr(1);
            }
            if (!targetFilePath.empty() && targetFilePath.back() != '\\' && targetFilePath.back() != '/') {
                 if (!relativeRedirectPath.empty() && relativeRedirectPath.front() != '\\' && relativeRedirectPath.front() != '/') {
                    targetFilePath += "\\";
                 } else if (relativeRedirectPath.empty()) {
                    targetFilePath += "\\";
                 }
            } else if (!targetFilePath.empty() && (targetFilePath.back() == '\\' || targetFilePath.back() == '/') && 
                       !relativeRedirectPath.empty() && (relativeRedirectPath.front() == '\\' || relativeRedirectPath.front() == '/')) {
                 relativeRedirectPath = relativeRedirectPath.substr(1);
            }

            targetFilePath += relativeRedirectPath;

            LogToFile("CreateFileA: Trying to redirect file \"" + fileNameStr + "\" (original pure: \"" + pureFileName + "\") to \"" + targetFilePath + "\"");

            HANDLE hFile = nativeCreateFileA(targetFilePath.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
            if (hFile != INVALID_HANDLE_VALUE) {
                std::stringstream logSsGeneric;
                logSsGeneric << "CreateFileA: Success, redirecting file: \"" << targetFilePath << "\", Handle: " << hFile;
                LogToFile(logSsGeneric.str());
            } else {
                LogToFile("CreateFileA: Fail to redirect file: \"" + targetFilePath + "\". Error: " + std::to_string(GetLastError()) + ". Falling back to original path: \"" + fileNameStr + "\"");
                return nativeCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
            }
            return hFile;
        }
    }

    return nativeCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
        g_hModule = hModule; 
		SetupPathsAndConfig(hModule); 
        LogToFile("DLL_PROCESS_ATTACH: reLoader attaching...");
		if (MH_Initialize() != MH_OK)
		{
            LogToFile("MH_Initialize failed!");
			MessageBox(NULL, L"Failed to initialize MinHook", L"Error", MB_OK | MB_ICONERROR);
			return FALSE;
		}

        LPVOID pTarget_CreateFileA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
		if (pTarget_CreateFileA && 
            (MH_CreateHook(pTarget_CreateFileA, &hooked_CreateFileA, reinterpret_cast<LPVOID*>(&nativeCreateFileA)) != MH_OK ||
            MH_EnableHook(pTarget_CreateFileA) != MH_OK) ) {
            LogToFile("ERROR: Failed to hook CreateFileA!"); 
            MessageBox(NULL, L"Failed to hook CreateFileA", L"Error", MB_OK | MB_ICONERROR);
            MH_Uninitialize(); 
            return FALSE;
		} else if (!pTarget_CreateFileA) { 
            LogToFile("ERROR: GetProcAddress for CreateFileA failed!");
            MessageBox(NULL, L"GetProcAddress for CreateFileA failed", L"Error", MB_OK | MB_ICONERROR);
            MH_Uninitialize();
            return FALSE;
        }
        
        LogToFile("reLoader attached!");
	}
		break;
	case DLL_PROCESS_DETACH:
	{
        LogToFile("DLL_PROCESS_DETACH: reLoader detaching...");
        LPVOID pTarget_CreateFileA_ForDisable = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
        if (pTarget_CreateFileA_ForDisable && nativeCreateFileA) { 
             MH_DisableHook(pTarget_CreateFileA_ForDisable);
        }
		MH_Uninitialize();
        LogToFile("DLL_PROCESS_DETACH: reLoader end...");
		LogToFile("");
	}
		break;
	}
	return TRUE;
}

//гавнокод