#include <windows.h>
#include <sddl.h>
#include <wincred.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <aclapi.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <cwctype>
#include <algorithm>
#include <lmaccess.h>
#include <lmapibuf.h>
#include <lmerr.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "netapi32.lib")

#ifndef DESKTOP_ALL_ACCESS
#define DESKTOP_ALL_ACCESS 0x01FF
#endif

// ---------------------------------------------------------------------------
// Global State & Configuration
// ---------------------------------------------------------------------------
static std::wstring g_Key              = L"Default";
static std::wstring g_User             = L"administrator";
static std::wstring g_Domain           = L".";
static std::wstring g_Target           = L"";
static std::wstring g_Cwd              = L"";
static std::wstring g_StaticArgs       = L"";
static std::wstring g_ClientArgs       = L"";
static bool         g_AllowClientArgs  = false;

static const BYTE kEntropy[] = {
    0x3A, 0x91, 0xC7, 0x04, 0xE2, 0x58, 0x1B, 0x6D,
    0xF0, 0x29, 0x84, 0xD5, 0x77, 0xAC, 0x42, 0x0E,
    0xBB, 0x63, 0x18, 0xDE, 0x55, 0x9F, 0x30, 0xC1,
    0x6A, 0xED, 0xA8, 0x12, 0x47, 0x70, 0xFA, 0x96
};

static SERVICE_STATUS_HANDLE g_hStatus    = nullptr;
static SERVICE_STATUS        g_Status{};
static HANDLE                g_hStopEvent = nullptr;
static HANDLE                g_hPipe      = INVALID_HANDLE_VALUE;

// ---------------------------------------------------------------------------
// Base File & String Helpers (Topological Order)
// ---------------------------------------------------------------------------
static std::wstring SelfPath()
{
    wchar_t self[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    return self;
}

static std::wstring SelfDir()
{
    std::wstring p = SelfPath();
    size_t idx = p.find_last_of(L"\\/");
    return (idx == std::wstring::npos) ? L"" : p.substr(0, idx + 1);
}

static std::wstring SanitizeIdentifier(const std::wstring& in)
{
    std::wstring out;
    for (wchar_t c : in) {
        if (std::iswalnum(c) || c == L'_' || c == L'-') {
            out.push_back(c);
        } else if (c == L'.' || c == L'\\') {
            out.push_back(L'_');
        }
    }
    return out.empty() ? L"default" : out;
}

static std::wstring GetProgramDataDir()
{
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &path))) {
        std::wstring dir = std::wstring(path) + L"\\LaunchAs\\";
        CoTaskMemFree(path);
        CreateDirectoryW(dir.c_str(), nullptr);
        return dir;
    }
    return SelfDir();
}

static std::wstring GetServiceName()
{
    return L"LaunchAs_" + SanitizeIdentifier(g_Key);
}

static std::wstring GetPipeName()
{
    return L"\\\\.\\pipe\\LaunchAsPipe_" + SanitizeIdentifier(g_Key);
}

static std::wstring GetLogPath()
{
    return GetProgramDataDir() + L"LaunchAs_" + SanitizeIdentifier(g_Key) + L".log";
}

// Credential path is derived strictly from Account Identity (Domain + Username) in ProgramData
static std::wstring GetAccountCredPath(const std::wstring& domain, const std::wstring& username)
{
    std::wstring domSan = (domain == L"." || domain.empty()) ? L"local" : SanitizeIdentifier(domain);
    std::wstring userSan = SanitizeIdentifier(username);
    return GetProgramDataDir() + L"account_" + domSan + L"_" + userSan + L".cred";
}

// ---------------------------------------------------------------------------
// Logging & Diagnostics
// ---------------------------------------------------------------------------
static void ServiceLog(const wchar_t* msg, DWORD code)
{
    wchar_t buf[512];
    swprintf_s(buf, L"%s  (error %lu / 0x%08lX)\r\n", msg, code, code);
    HANDLE h = CreateFileW(GetLogPath().c_str(),
                           FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, buf, static_cast<DWORD>(wcslen(buf) * sizeof(wchar_t)), &w, nullptr);
        CloseHandle(h);
    }
}

static void ShowError(const wchar_t* msg, DWORD code)
{
    wchar_t buf[512];
    swprintf_s(buf, L"%s\r\n\r\nWindows error %lu (0x%08lX)", msg, code, code);
    MessageBoxW(nullptr, buf, L"Launch As", MB_ICONERROR | MB_OK | MB_TOPMOST | MB_SETFOREGROUND);
}

// ---------------------------------------------------------------------------
// Resolve the True Primary Local Administrator (RID 500) or First Local Admin
// ---------------------------------------------------------------------------
static bool GetPrimaryAdminAccount(std::wstring& user, std::wstring& domain)
{
    // Retrieve local computer name for comparison
    wchar_t localMachine[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD cchMachine = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(localMachine, &cchMachine);

    // 1. Try to resolve the true RID-500 built-in Administrator (even if renamed or localized)
    BYTE adminSid[SECURITY_MAX_SID_SIZE]{};
    DWORD cbSid = sizeof(adminSid);
    if (CreateWellKnownSid(WinAccountAdministratorSid, nullptr, reinterpret_cast<PSID>(adminSid), &cbSid)) {
        wchar_t nameBuf[CREDUI_MAX_USERNAME_LENGTH + 1]{};
        DWORD cchName = CREDUI_MAX_USERNAME_LENGTH + 1;
        wchar_t domBuf[CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1]{};
        DWORD cchDom = CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1;
        SID_NAME_USE snu;

        if (LookupAccountSidW(nullptr, reinterpret_cast<PSID>(adminSid), nameBuf, &cchName, domBuf, &cchDom, &snu)) {
            user = nameBuf;
            // If domain matches the local computer name, normalize to "." for clean local auth
            if (cchDom == 0 || _wcsicmp(domBuf, localMachine) == 0) {
                domain = L".";
            } else {
                domain = domBuf;
            }
            return true;
        }
    }

    // 2. Fallback: Query the localized "Administrators" group (Builtin\Administrators SID = S-1-5-32-544)
    BYTE adminGroupSid[SECURITY_MAX_SID_SIZE]{};
    DWORD cbGroupSid = sizeof(adminGroupSid);
    if (CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, reinterpret_cast<PSID>(adminGroupSid), &cbGroupSid)) {
        wchar_t groupName[256]{};
        DWORD cchGroupName = 256;
        wchar_t groupDom[256]{};
        DWORD cchGroupDom = 256;
        SID_NAME_USE snu;

        if (LookupAccountSidW(nullptr, reinterpret_cast<PSID>(adminGroupSid), groupName, &cchGroupName, groupDom, &cchGroupDom, &snu)) {
            LOCALGROUP_MEMBERS_INFO_3* pMembers = nullptr;
            DWORD entriesRead = 0, totalEntries = 0;
            DWORD_PTR resumeHandle = 0;

            NET_API_STATUS status = NetLocalGroupGetMembers(
                nullptr, groupName, 3,
                reinterpret_cast<LPBYTE*>(&pMembers),
                MAX_PREFERRED_LENGTH,
                &entriesRead, &totalEntries, &resumeHandle);

            if (status == NERR_Success && pMembers && entriesRead > 0) {
                std::wstring raw = pMembers[0].lgrmi3_domainandname;
                size_t pos = raw.find(L'\\');
                if (pos != std::wstring::npos) {
                    std::wstring parsedDom = raw.substr(0, pos);
                    user = raw.substr(pos + 1);
                    if (_wcsicmp(parsedDom.c_str(), localMachine) == 0) {
                        domain = L".";
                    } else {
                        domain = parsedDom;
                    }
                } else {
                    domain = L".";
                    user = raw;
                }
                NetApiBufferFree(pMembers);
                return true;
            }
            if (pMembers) NetApiBufferFree(pMembers);
        }
    }

    return false;
}

static bool SaveEncrypted(const std::wstring& path, const std::wstring& secret)
{
    DATA_BLOB in{}, out{}, ent{};
    in.pbData  = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(secret.c_str()));
    in.cbData  = static_cast<DWORD>((secret.size() + 1) * sizeof(wchar_t));
    ent.pbData = const_cast<BYTE*>(kEntropy);
    ent.cbData = sizeof(kEntropy);

    if (!CryptProtectData(&in, L"LaunchAs account credential", &ent, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE, &out)) {
        return false;
    }

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    bool ok = false;
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        ok = WriteFile(h, out.pbData, out.cbData, &written, nullptr) && (written == out.cbData);
        CloseHandle(h);
    }
    LocalFree(out.pbData);
    return ok;
}

static bool LoadDecrypted(const std::wstring& path, std::wstring& secret)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD size = GetFileSize(h, nullptr);
    if (size == 0 || size == INVALID_FILE_SIZE) {
        CloseHandle(h);
        return false;
    }

    std::vector<BYTE> buf(size);
    DWORD read = 0;
    bool ok = ReadFile(h, buf.data(), size, &read, nullptr) && (read == size);
    CloseHandle(h);
    if (!ok) return false;

    DATA_BLOB in{ size, buf.data() }, out{}, ent{};
    ent.pbData = const_cast<BYTE*>(kEntropy);
    ent.cbData = sizeof(kEntropy);

    if (CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, 0, &out)) {
        secret.assign(reinterpret_cast<wchar_t*>(out.pbData));
        LocalFree(out.pbData);
        ok = true;
    } else {
        ok = false;
    }
    SecureZeroMemory(buf.data(), size);
    return ok;
}

static bool PromptForPassword(std::wstring& user, std::wstring& domain, std::wstring& password)
{
    CREDUI_INFOW ui{};
    ui.cbSize = sizeof(ui);
    ui.hwndParent = GetForegroundWindow();
    if (!ui.hwndParent) ui.hwndParent = GetDesktopWindow();
    ui.pszCaptionText = L"Launch As - Account Setup";
    ui.pszMessageText =
        L"Enter the credentials for the designated administrative account.\r\n"
        L"The password will be stored encrypted (machine-bound) on this system.";

    std::wstring inUser = user;
    if (!domain.empty() && domain != L".") {
        inUser = domain + L"\\" + user;
    }

    PVOID inAuthBuffer = nullptr;
    ULONG inAuthBufferSize = 0;

    if (!inUser.empty()) {
        CredPackAuthenticationBufferW(0, const_cast<LPWSTR>(inUser.c_str()), const_cast<LPWSTR>(L""), nullptr, &inAuthBufferSize);
        if (inAuthBufferSize > 0) {
            inAuthBuffer = CoTaskMemAlloc(inAuthBufferSize);
            if (inAuthBuffer) {
                CredPackAuthenticationBufferW(0, const_cast<LPWSTR>(inUser.c_str()), const_cast<LPWSTR>(L""),
                                              reinterpret_cast<PBYTE>(inAuthBuffer), &inAuthBufferSize);
            }
        }
    }

    PVOID outAuthBuffer = nullptr;
    ULONG outAuthBufferSize = 0;
    BOOL save = FALSE;
    ULONG authPackage = 0;

    DWORD err = CredUIPromptForWindowsCredentialsW(
        &ui,
        0,                                   // dwAuthError: 0 = clean prompt
        &authPackage,
        inAuthBuffer, inAuthBufferSize,      
        &outAuthBuffer, &outAuthBufferSize,  
        &save,
        CREDUIWIN_GENERIC);

    if (inAuthBuffer) {
        CoTaskMemFree(inAuthBuffer);
    }

    if (err != ERROR_SUCCESS || !outAuthBuffer) {
        return false;
    }

    wchar_t userBuf[CREDUI_MAX_USERNAME_LENGTH + 1]{};
    DWORD userLen = CREDUI_MAX_USERNAME_LENGTH + 1;
    wchar_t domBuf[CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1]{};
    DWORD domLen = CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1;
    wchar_t passBuf[CREDUI_MAX_PASSWORD_LENGTH + 1]{};
    DWORD passLen = CREDUI_MAX_PASSWORD_LENGTH + 1;

    BOOL unpackOk = CredUnPackAuthenticationBufferW(
        0,
        outAuthBuffer, outAuthBufferSize,
        userBuf, &userLen,
        domBuf, &domLen,
        passBuf, &passLen);

    SecureZeroMemory(outAuthBuffer, outAuthBufferSize);
    CoTaskMemFree(outAuthBuffer);

    if (!unpackOk) {
        SecureZeroMemory(passBuf, sizeof(passBuf));
        return false;
    }

    user = userBuf;

    wchar_t localMachine[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD cchMachine = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(localMachine, &cchMachine);

    if (wcslen(domBuf) == 0 || _wcsicmp(domBuf, localMachine) == 0) {
        domain = L".";
    } else {
        domain = domBuf;
    }

    password = passBuf;
    SecureZeroMemory(passBuf, sizeof(passBuf));
    return true;
}

// ---------------------------------------------------------------------------
// SCM Inspection: Check if an account is still referenced by any other LaunchAs service
// ---------------------------------------------------------------------------
static bool IsAccountUsedByOtherServices(const std::wstring& domain, const std::wstring& username, const std::wstring& currentKey)
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return true; // Fail safe

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    if (bytesNeeded == 0) {
        CloseServiceHandle(hSCM);
        return false;
    }

    std::vector<BYTE> buf(bytesNeeded);
    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
        CloseServiceHandle(hSCM);
        return true;
    }

    auto* pServices = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    std::wstring currentSvcName = GetServiceName();
    std::wstring targetMatch = L"/user=\"" + username + L"\"";

    bool stillInUse = false;

    for (DWORD i = 0; i < servicesReturned; ++i) {
        std::wstring name = pServices[i].lpServiceName;
        if (name.find(L"LaunchAs_") == 0 && _wcsicmp(name.c_str(), currentSvcName.c_str()) != 0) {
            SC_HANDLE hOther = OpenServiceW(hSCM, name.c_str(), SERVICE_QUERY_CONFIG);
            if (hOther) {
                DWORD cfgNeeded = 0;
                QueryServiceConfigW(hOther, nullptr, 0, &cfgNeeded);
                if (cfgNeeded > 0) {
                    std::vector<BYTE> cfgBuf(cfgNeeded);
                    auto* pConfig = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
                    if (QueryServiceConfigW(hOther, pConfig, cfgNeeded, &cfgNeeded)) {
                        std::wstring binPath = pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : L"";
                        if (_wcsicmp(binPath.c_str(), targetMatch.c_str()) != 0 || 
                            binPath.find(username) != std::wstring::npos) {
                            stillInUse = true;
                            CloseServiceHandle(hOther);
                            break;
                        }
                    }
                }
                CloseServiceHandle(hOther);
            }
        }
    }

    CloseServiceHandle(hSCM);
    return stillInUse;
}

// ---------------------------------------------------------------------------
// Elevation Utilities
// ---------------------------------------------------------------------------
static bool IsElevated()
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return false;
    TOKEN_ELEVATION elev{};
    DWORD size = sizeof(elev);
    bool ok = GetTokenInformation(hToken, TokenElevation, &elev, size, &size);
    CloseHandle(hToken);
    return ok && elev.TokenIsElevated;
}

static void SelfElevate()
{
    std::wstring self = SelfPath();
    
    LPCWSTR pCmd = GetCommandLineW();
    
    // Skip executable path cleanly
    if (*pCmd == L'"') {
        ++pCmd;
        while (*pCmd && *pCmd != L'"') ++pCmd;
        if (*pCmd == L'"') ++pCmd;
    } else {
        while (*pCmd && *pCmd != L' ' && *pCmd != L'\t') ++pCmd;
    }
    while (*pCmd == L' ' || *pCmd == L'\t') ++pCmd;

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = self.c_str();
    sei.lpParameters = pCmd;
    sei.nShow = SW_SHOWNORMAL;
    ShellExecuteExW(&sei);
}

// ---------------------------------------------------------------------------
// Interactive Desktop & Session Token Bridging
// ---------------------------------------------------------------------------
static BOOL AddSidToObjectDacl(HANDLE hObj, PSID pSid, DWORD accessMask)
{
    SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;

    DWORD needed = 0;
    GetUserObjectSecurity(hObj, &si, nullptr, 0, &needed);
    if (needed == 0) return FALSE;

    std::vector<BYTE> sdBuf(needed);
    if (!GetUserObjectSecurity(hObj, &si, sdBuf.data(), needed, &needed))
        return FALSE;

    auto* pSD = reinterpret_cast<SECURITY_DESCRIPTOR*>(sdBuf.data());

    BOOL daclPresent = FALSE, daclDefaulted = FALSE;
    ACL* pOldAcl = nullptr;
    if (!GetSecurityDescriptorDacl(pSD, &daclPresent, &pOldAcl, &daclDefaulted))
        return FALSE;

    DWORD sidLen = GetLengthSid(pSid);
    DWORD oldAceBytes = (daclPresent && pOldAcl) ? pOldAcl->AclSize - sizeof(ACL) : 0;
    DWORD newAclSize = sizeof(ACL) + oldAceBytes + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + sidLen;

    std::vector<BYTE> aclBuf(newAclSize);
    auto* pNewAcl = reinterpret_cast<ACL*>(aclBuf.data());
    if (!InitializeAcl(pNewAcl, newAclSize, ACL_REVISION))
        return FALSE;

    if (daclPresent && pOldAcl) {
        for (DWORD i = 0; i < pOldAcl->AceCount; ++i) {
            void* pAce = nullptr;
            if (GetAce(pOldAcl, i, &pAce)) {
                auto* hdr = reinterpret_cast<ACE_HEADER*>(pAce);
                if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pAce, hdr->AceSize))
                    return FALSE;
            }
        }
    }

    if (!AddAccessAllowedAce(pNewAcl, ACL_REVISION, accessMask, pSid))
        return FALSE;

    SECURITY_DESCRIPTOR newSD{};
    if (!InitializeSecurityDescriptor(&newSD, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&newSD, TRUE, pNewAcl, FALSE))
        return FALSE;

    return SetUserObjectSecurity(hObj, &si, &newSD);
}

static void GrantCurrentSessionDesktopAccess()
{
    BYTE sidBuf[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sidBuf);
    if (!CreateWellKnownSid(WinWorldSid, nullptr, reinterpret_cast<PSID>(sidBuf), &sidSize))
        return;
    PSID pSid = reinterpret_cast<PSID>(sidBuf);

    HWINSTA hWinsta = OpenWindowStationW(L"winsta0", FALSE, READ_CONTROL | WRITE_DAC);
    if (hWinsta) {
        AddSidToObjectDacl(hWinsta, pSid, WINSTA_ALL_ACCESS);
        CloseWindowStation(hWinsta);
    }

    HDESK hDesk = OpenDesktopW(L"default", 0, FALSE, READ_CONTROL | WRITE_DAC);
    if (hDesk) {
        AddSidToObjectDacl(hDesk, pSid, DESKTOP_ALL_ACCESS);
        CloseDesktop(hDesk);
    }
}

static DWORD GetActiveInteractiveSessionId()
{
    WTS_SESSION_INFOW* pSessions = nullptr;
    DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &count)) {
        DWORD result = 0xFFFFFFFF;
        for (DWORD i = 0; i < count; ++i) {
            if (pSessions[i].State == WTSActive && pSessions[i].SessionId != 0) {
                result = pSessions[i].SessionId;
                break;
            }
        }
        WTSFreeMemory(pSessions);
        if (result != 0xFFFFFFFF) return result;
    }
    return WTSGetActiveConsoleSessionId();
}

// ---------------------------------------------------------------------------
// Asynchronous Process Cleanup (Preserves HKCU Profile During Execution)
// ---------------------------------------------------------------------------
struct ProcessCleanupContext {
    HANDLE hProcess;
    HANDLE hAdminToken;
    PROFILEINFOW piEnv;
    BOOL profileLoaded;
    LPVOID envBlock;
};

static DWORD WINAPI ProcessCleanupThread(LPVOID param)
{
    auto* ctx = reinterpret_cast<ProcessCleanupContext*>(param);
    if (ctx) {
        if (ctx->hProcess && ctx->hProcess != INVALID_HANDLE_VALUE) {
            WaitForSingleObject(ctx->hProcess, INFINITE);
            CloseHandle(ctx->hProcess);
        }
        if (ctx->envBlock) {
            DestroyEnvironmentBlock(ctx->envBlock);
        }
        if (ctx->profileLoaded && ctx->hAdminToken) {
            UnloadUserProfile(ctx->hAdminToken, ctx->piEnv.hProfile);
        }
        if (ctx->hAdminToken) {
            CloseHandle(ctx->hAdminToken);
        }
        delete ctx;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Elevated Process Spawning
// ---------------------------------------------------------------------------
static BOOL LaunchInActiveSession(const std::wstring& targetExecutable,
                                  const std::wstring& staticArgs,
                                  const std::wstring& clientDynamicArgs,
                                  const std::wstring& workingDirectory,
                                  const std::wstring& username,
                                  const std::wstring& domain,
                                  const std::wstring& password,
                                  DWORD& outPid)
{
    outPid = 0;

    if (targetExecutable.empty()) {
        ServiceLog(L"Launch failed: target executable is empty", 0);
        return FALSE;
    }

    DWORD sessionId = GetActiveInteractiveSessionId();
    if (sessionId == 0xFFFFFFFF) {
        ServiceLog(L"GetActiveInteractiveSessionId failed", GetLastError());
        return FALSE;
    }

    HANDLE hToken = nullptr;
    if (!LogonUserW(username.c_str(), domain.c_str(), password.c_str(),
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        ServiceLog(L"LogonUser failed", GetLastError());
        return FALSE;
    }

    HANDLE hAdmin = nullptr;
    TOKEN_LINKED_TOKEN lt{};
    DWORD need = 0;
    if (GetTokenInformation(hToken, TokenLinkedToken, &lt, sizeof(lt), &need) && lt.LinkedToken) {
        hAdmin = lt.LinkedToken;
    } else {
        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr,
                              SecurityImpersonation, TokenPrimary, &hAdmin)) {
            ServiceLog(L"DuplicateTokenEx failed", GetLastError());
            CloseHandle(hToken);
            return FALSE;
        }
    }
    CloseHandle(hToken);

    if (!SetTokenInformation(hAdmin, TokenSessionId, &sessionId, sizeof(sessionId))) {
        ServiceLog(L"SetTokenInformation failed", GetLastError());
        CloseHandle(hAdmin);
        return FALSE;
    }

    auto* ctx = new ProcessCleanupContext{};
    ctx->hAdminToken = hAdmin;
    ctx->piEnv.dwSize = sizeof(PROFILEINFOW);
    ctx->piEnv.lpUserName = const_cast<wchar_t*>(username.c_str());

    ctx->profileLoaded = LoadUserProfileW(hAdmin, &ctx->piEnv);
    if (!ctx->profileLoaded) {
        ServiceLog(L"LoadUserProfile failed", GetLastError());
    }

    if (!CreateEnvironmentBlock(&ctx->envBlock, hAdmin, TRUE)) {
        ServiceLog(L"CreateEnvironmentBlock failed", GetLastError());
        ctx->envBlock = nullptr;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    PROCESS_INFORMATION pi{};
    
    // 1. Properly quote executable if unquoted and containing spaces
    std::wstring finalCmd;
    if (targetExecutable.front() == L'"') {
        finalCmd = targetExecutable;
    } else if (targetExecutable.find(L' ') != std::wstring::npos) {
        finalCmd = L"\"" + targetExecutable + L"\"";
    } else {
        finalCmd = targetExecutable;
    }

    if (!staticArgs.empty()) {
        finalCmd += L" " + staticArgs;
    }
    if (g_AllowClientArgs && !clientDynamicArgs.empty()) {
        finalCmd += L" " + clientDynamicArgs;
    }

    // 2. Working directory fallback: derive from target executable directory if omitted
    std::wstring effectiveCwd = workingDirectory;
    if (effectiveCwd.empty()) {
        std::wstring cleanTarget = targetExecutable;
        if (cleanTarget.size() >= 2 && cleanTarget.front() == L'"' && cleanTarget.back() == L'"') {
            cleanTarget = cleanTarget.substr(1, cleanTarget.size() - 2);
        }
        size_t lastSlash = cleanTarget.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            effectiveCwd = cleanTarget.substr(0, lastSlash);
        }
    }
    LPCWSTR lpCwd = effectiveCwd.empty() ? nullptr : effectiveCwd.c_str();

    std::vector<wchar_t> cmdBuf(finalCmd.begin(), finalCmd.end());
    cmdBuf.push_back(L'\0');

    BOOL ok = CreateProcessAsUserW(
        hAdmin,
        nullptr,
        cmdBuf.data(),
        nullptr, nullptr, FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        ctx->envBlock,
        lpCwd,
        &si, &pi);

    if (ok) {
        outPid = pi.dwProcessId;
        ServiceLog(L"CreateProcessAsUser succeeded, PID", pi.dwProcessId);
        CloseHandle(pi.hThread);
        ctx->hProcess = pi.hProcess;

        HANDLE hThread = CreateThread(nullptr, 0, ProcessCleanupThread, ctx, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    } else {
        ServiceLog(L"CreateProcessAsUser failed", GetLastError());
        if (ctx->envBlock) DestroyEnvironmentBlock(ctx->envBlock);
        if (ctx->profileLoaded) UnloadUserProfile(hAdmin, ctx->piEnv.hProfile);
        CloseHandle(hAdmin);
        delete ctx;
    }

    return ok;
}

// ---------------------------------------------------------------------------
// Named Pipe IPC Listener (Service Worker Thread - Resilient)
// ---------------------------------------------------------------------------
static DWORD WINAPI PipeListenerThread(LPVOID)
{
    ServiceLog(L"Service listener thread started", 0);

    std::wstring credPath = GetAccountCredPath(g_Domain, g_User);
    ServiceLog((L"Target credential path: " + credPath).c_str(), 0);

    std::wstring password;
    if (!LoadDecrypted(credPath, password)) {
        ServiceLog(L"WARNING: Credential not decrypted at startup (will retry on launch request)", GetLastError());
    } else {
        ServiceLog(L"Account credential pre-loaded successfully", 0);
    }

    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GRGW;;;WD)", SDDL_REVISION_1, &pSD, nullptr)) {
        ServiceLog(L"SDDL conversion failed", GetLastError());
        return 1;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    std::wstring pipeName = GetPipeName();
    ServiceLog((L"Creating Named Pipe: " + pipeName).c_str(), 0);

    while (true) {
        g_hPipe = CreateNamedPipeW(pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 8192, 8192, 0, &sa);

        if (g_hPipe == INVALID_HANDLE_VALUE) {
            ServiceLog(L"CreateNamedPipe failed", GetLastError());
            break;
        }

        if (ConnectNamedPipe(g_hPipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::vector<wchar_t> inBuf(8192, 0);
            DWORD bytesRead = 0;
            if (ReadFile(g_hPipe, inBuf.data(), static_cast<DWORD>((inBuf.size() - 1) * sizeof(wchar_t)), &bytesRead, nullptr)) {
                std::wstring request = inBuf.data();
                
                if (request.find(L"LAUNCH") == 0) {
                    ServiceLog(L"LAUNCH request received from client", 0);

                    if (password.empty()) {
                        if (!LoadDecrypted(credPath, password)) {
                            ServiceLog(L"LoadDecrypted failed during client request", GetLastError());
                        }
                    }

                    BOOL launched = FALSE;
                    if (!password.empty()) {
                        std::wstring clientArgs = L"";
                        size_t p1 = request.find(L'\n');
                        if (p1 != std::wstring::npos) {
                            clientArgs = request.substr(p1 + 1);
                        }

                        if (!clientArgs.empty() && !g_AllowClientArgs) {
                            ServiceLog(L"Warning: Dynamic client args supplied but not allowed. Dropping args.", 0);
                            clientArgs.clear();
                        }

                        DWORD launchedPid = 0;
                        launched = LaunchInActiveSession(g_Target, g_StaticArgs, clientArgs, g_Cwd, g_User, g_Domain, password, launchedPid);

                        char resp[64]{};
                        if (launched && launchedPid != 0) {
                            sprintf_s(resp, "OK|%lu", launchedPid);
                        } else {
                            strcpy_s(resp, "FAIL");
                        }

                        DWORD written = 0;
                        WriteFile(g_hPipe, resp, static_cast<DWORD>(strlen(resp)), &written, nullptr);
                    } else {
                        const char* resp = "FAIL";
                        DWORD written = 0;
                        WriteFile(g_hPipe, resp, static_cast<DWORD>(strlen(resp)), &written, nullptr);
                    }
                }
            }
        }
        DisconnectNamedPipe(g_hPipe);
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;

        if (WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0) break;
    }

    LocalFree(pSD);
    SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
    return 0;
}

// ---------------------------------------------------------------------------
// Service Control Manager Callbacks
// ---------------------------------------------------------------------------
static VOID WINAPI ServiceCtrlHandler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP) {
        g_Status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_hStatus, &g_Status);
        SetEvent(g_hStopEvent);
    }
}

static VOID WINAPI ServiceMain(DWORD, LPWSTR*)
{
    std::wstring serviceName = GetServiceName();
    g_hStatus = RegisterServiceCtrlHandlerW(serviceName.c_str(), ServiceCtrlHandler);
    if (!g_hStatus) {
        g_hStatus = RegisterServiceCtrlHandlerW(L"", ServiceCtrlHandler);
    }
    if (!g_hStatus) return;

    g_Status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwCurrentState     = SERVICE_START_PENDING;
    g_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_hStatus, &g_Status);

    g_hStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    HANDLE hThread = CreateThread(nullptr, 0, PipeListenerThread, nullptr, 0, nullptr);

    if (!g_hStopEvent || !hThread) {
        g_Status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_hStatus, &g_Status);
        return;
    }

    g_Status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_hStatus, &g_Status);

    WaitForSingleObject(g_hStopEvent, INFINITE);

    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);
    CloseHandle(g_hStopEvent);

    g_Status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_hStatus, &g_Status);
}

// ---------------------------------------------------------------------------
// SCM Registration Helper: Escapes values for CommandLineToArgvW compatibility
// ---------------------------------------------------------------------------
static std::wstring EscapeForCommandLine(const std::wstring& arg)
{
    if (arg.empty()) return L"\"\"";

    std::wstring out = L"\"";
    for (size_t i = 0; i < arg.size(); ++i) {
        if (arg[i] == L'"') {
            out += L"\\\"";
        } else if (arg[i] == L'\\') {
            size_t count = 1;
            while (i + 1 < arg.size() && arg[i + 1] == L'\\') {
                ++count;
                ++i;
            }
            if (i + 1 == arg.size()) {
                out.append(count * 2, L'\\');
            } else if (arg[i + 1] == L'"') {
                out.append(count * 2 + 1, L'\\');
            } else {
                out.append(count, L'\\');
            }
        } else {
            out.push_back(arg[i]);
        }
    }
    out += L"\"";
    return out;
}

static DWORD InstallAndStartService()
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return GetLastError();

    std::wstring serviceName = GetServiceName();
    std::wstring displayName = L"Launch As Service (" + SanitizeIdentifier(g_Key) + L")";
    
    std::wstring cmd = L"\"" + SelfPath() + L"\" /service"
                     + L" /key=" + EscapeForCommandLine(g_Key)
                     + L" /user=" + EscapeForCommandLine(g_User)
                     + L" /domain=" + EscapeForCommandLine(g_Domain)
                     + L" /target=" + EscapeForCommandLine(g_Target)
                     + L" /cwd=" + EscapeForCommandLine(g_Cwd);

    if (!g_StaticArgs.empty()) {
        cmd += L" /args=" + EscapeForCommandLine(g_StaticArgs);
    }
    if (g_AllowClientArgs) {
        cmd += L" /allow_client_args";
    }

    SC_HANDLE hSvc = CreateServiceW(hSCM, serviceName.c_str(), displayName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hSvc = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
            if (!hSvc) {
                CloseServiceHandle(hSCM);
                return GetLastError();
            }

            if (!ChangeServiceConfigW(
                    hSvc,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    cmd.c_str(),
                    nullptr, nullptr, nullptr, nullptr, nullptr,
                    displayName.c_str()))
            {
                DWORD cfgErr = GetLastError();
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSCM);
                return cfgErr;
            }

            SERVICE_STATUS ss{};
            ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
            for (int i = 0; i < 20; ++i) {
                QueryServiceStatus(hSvc, &ss);
                if (ss.dwCurrentState == SERVICE_STOPPED) break;
                Sleep(250);
            }
        } else {
            CloseServiceHandle(hSCM);
            return err;
        }
    }

    DWORD err = ERROR_SUCCESS;
    for (int retry = 0; retry < 5; ++retry) {
        if (StartServiceW(hSvc, 0, nullptr)) {
            err = ERROR_SUCCESS;
            break;
        }
        err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            err = ERROR_SUCCESS;
            break;
        }
        Sleep(100);
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return err;
}

static DWORD StopAndRemoveService()
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return GetLastError();

    std::wstring serviceName = GetServiceName();
    SC_HANDLE hSvc = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            return ERROR_SUCCESS;
        }
        return err;
    }

    SERVICE_STATUS ss{};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    for (int i = 0; i < 30; ++i) {
        QueryServiceStatus(hSvc, &ss);
        if (ss.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(500);
    }
    BOOL ok = DeleteService(hSvc);
    DWORD err = ok ? ERROR_SUCCESS : GetLastError();
    if (err == ERROR_SERVICE_MARKED_FOR_DELETE || err == ERROR_SERVICE_DOES_NOT_EXIST) {
        err = ERROR_SUCCESS;
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return err;
}

// ---------------------------------------------------------------------------
// Client-Side Foreground Acquisition
// ---------------------------------------------------------------------------
struct ClientForegroundCtx {
    DWORD dwProcessId;
    HWND  hFoundWnd;
};

static BOOL CALLBACK EnumClientWindows(HWND hwnd, LPARAM lParam)
{
    auto* ctx = reinterpret_cast<ClientForegroundCtx*>(lParam);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == ctx->dwProcessId && IsWindowVisible(hwnd)) {
        LONG style = GetWindowLongW(hwnd, GWL_STYLE);
        if (style & WS_VISIBLE) {
            ctx->hFoundWnd = hwnd;
            return FALSE;
        }
    }
    return TRUE;
}

static void ForceProcessToForeground(DWORD targetPid)
{
    if (targetPid == 0) return;

    ClientForegroundCtx ctx{ targetPid, nullptr };

    for (int i = 0; i < 30; ++i) {
        EnumWindows(EnumClientWindows, reinterpret_cast<LPARAM>(&ctx));
        if (ctx.hFoundWnd) break;
        Sleep(100);
    }

    if (ctx.hFoundWnd) {
        DWORD foregroundThreadId = GetWindowThreadProcessId(GetForegroundWindow(), nullptr);
        DWORD currentThreadId    = GetCurrentThreadId();
        DWORD targetThreadId     = GetWindowThreadProcessId(ctx.hFoundWnd, nullptr);

        if (foregroundThreadId != currentThreadId) {
            AttachThreadInput(currentThreadId, foregroundThreadId, TRUE);
        }
        if (targetThreadId != currentThreadId) {
            AttachThreadInput(currentThreadId, targetThreadId, TRUE);
        }

        ShowWindow(ctx.hFoundWnd, SW_SHOWNORMAL);
        SetWindowPos(ctx.hFoundWnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetForegroundWindow(ctx.hFoundWnd);
        BringWindowToTop(ctx.hFoundWnd);
        SetFocus(ctx.hFoundWnd);

        if (foregroundThreadId != currentThreadId) {
            AttachThreadInput(currentThreadId, foregroundThreadId, FALSE);
        }
        if (targetThreadId != currentThreadId) {
            AttachThreadInput(currentThreadId, targetThreadId, FALSE);
        }
    }
}

// ---------------------------------------------------------------------------
// Client Execution Mode (Non-Admin Invocation)
// ---------------------------------------------------------------------------
static int RunClient()
{
    GrantCurrentSessionDesktopAccess();

    std::wstring pipeName = GetPipeName();
    HANDLE hPipe = CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) {
            std::wstring msg = L"The Launch As Service (" + SanitizeIdentifier(g_Key) + L") is not running.\r\n"
                               L"An administrator must run /register /key=\"" + g_Key + L"\" first.";
            ShowError(msg.c_str(), err);
        } else {
            ShowError(L"Failed to connect to the Launch As Service pipe.", err);
        }
        return 2;
    }

    std::wstring payload = L"LAUNCH";
    if (!g_ClientArgs.empty()) {
        payload += L"\n" + g_ClientArgs;
    }

    DWORD bytesToWrite = static_cast<DWORD>(payload.size() * sizeof(wchar_t));
    DWORD written = 0;

    AllowSetForegroundWindow(ASFW_ANY);

    if (!WriteFile(hPipe, payload.c_str(), bytesToWrite, &written, nullptr)) {
        DWORD err = GetLastError();
        CloseHandle(hPipe);
        ShowError(L"Failed to send launch request to the service.", err);
        return 3;
    }

    char buf[64]{};
    DWORD read = 0;
    if (!ReadFile(hPipe, buf, sizeof(buf) - 1, &read, nullptr)) {
        DWORD err = GetLastError();
        CloseHandle(hPipe);
        ShowError(L"Failed to read response from the service.", err);
        return 4;
    }
    CloseHandle(hPipe);

    if (strncmp(buf, "OK", 2) != 0) {
        std::wstring msg = L"The service failed to launch the application.\r\nCheck " + GetLogPath() + L" for details.";
        ShowError(msg.c_str(), 0);
        return 5;
    }

    DWORD childPid = 0;
    if (buf[2] == '|' && strlen(buf) > 3) {
        childPid = static_cast<DWORD>(strtoul(buf + 3, nullptr, 10));
    }

    if (childPid != 0) {
        ForceProcessToForeground(childPid);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Command Line Parsing Helpers
// ---------------------------------------------------------------------------
static bool HasFlag(int argc, wchar_t* argv[], const wchar_t* flag)
{
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], flag) == 0) return true;
    }
    return false;
}

static std::wstring GetNamedParam(int argc, wchar_t* argv[], const wchar_t* paramName)
{
    std::wstring p = paramName;
    while (!p.empty() && (p.back() == L'=' || p.back() == L':')) {
        p.pop_back();
    }

    std::wstring prefixEq = p + L"=";
    std::wstring prefixCol = p + L":";

    for (int i = 1; i < argc; ++i) {
        std::wstring raw;

        if (_wcsnicmp(argv[i], prefixEq.c_str(), prefixEq.size()) == 0) {
            raw = argv[i] + prefixEq.size();
        } else if (_wcsnicmp(argv[i], prefixCol.c_str(), prefixCol.size()) == 0) {
            raw = argv[i] + prefixCol.size();
        } else if (_wcsicmp(argv[i], p.c_str()) == 0 && (i + 1 < argc)) {
            if (argv[i + 1][0] != L'/' && argv[i + 1][0] != L'-') {
                raw = argv[i + 1];
            }
        }

        if (!raw.empty()) {
            size_t first = raw.find_first_not_of(L" \t\r\n");
            size_t last  = raw.find_last_not_of(L" \t\r\n");
            if (first == std::wstring::npos) return L"";
            raw = raw.substr(first, (last - first + 1));

            if (raw.size() >= 2 && raw.front() == L'"' && raw.back() == L'"') {
                raw = raw.substr(1, raw.size() - 2);
            }
            return raw;
        }
    }
    return L"";
}

// ---------------------------------------------------------------------------
// Program Entry Point
// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || argc < 1) return 1;

    std::wstring parsedKey    = GetNamedParam(argc, argv, L"/key");
    std::wstring parsedUser   = GetNamedParam(argc, argv, L"/user");
    std::wstring parsedDomain = GetNamedParam(argc, argv, L"/domain");
    std::wstring parsedTarget = GetNamedParam(argc, argv, L"/target");
    std::wstring parsedCwd    = GetNamedParam(argc, argv, L"/cwd");
    std::wstring parsedArgs   = GetNamedParam(argc, argv, L"/args");
    std::wstring parsedPass   = GetNamedParam(argc, argv, L"/reckless_password");

    if (!parsedKey.empty())    g_Key    = parsedKey;
    if (!parsedUser.empty())   g_User   = parsedUser;
    if (!parsedDomain.empty()) g_Domain = parsedDomain;
    if (!parsedTarget.empty()) g_Target = parsedTarget;
    if (!parsedCwd.empty())    g_Cwd    = parsedCwd;

    bool isHelp = HasFlag(argc, argv, L"/?") || 
                  HasFlag(argc, argv, L"/help") || 
                  HasFlag(argc, argv, L"/about") || 
                  HasFlag(argc, argv, L"-h") || 
                  HasFlag(argc, argv, L"--help");

    if (isHelp) {
        std::wstring aboutMsg =
            L"Launch As - Windows Elevation & Session Bridge Utility\r\n"
            L"Version 1.0.0 (x64 Release)\r\n\r\n"
            L"USAGE:\r\n"
            L"  Register: LaunchAs.exe /register /key=\"Name\" /target=\"Path\" [/cwd=\"Path\"]\r\n"
            L"  Launch:   LaunchAs.exe /key=\"Name\" [/args=\"...\"]\r\n"
            L"  Remove:   LaunchAs.exe /remove /key=\"Name\"\r\n\r\n"
            L"SECURITY:\r\n"
            L"  Credentials are encrypted locally via DPAPI machine-keys.\r\n"
            L"  Never elevate applications with unconstrained Common File Dialogs.\r\n\r\n"
            L"🎗️ SUPPORT THE AUTHOR:\r\n"
            L"  If this tool provides value to your organization, please consider\r\n"
            L"  supporting my cancer treatment campaign:\r\n"
            L"  https://www.givesendgo.com/stalwart";

        MessageBoxW(nullptr, aboutMsg.c_str(), L"About Launch As", 
                    MB_ICONINFORMATION | MB_OK | MB_TOPMOST | MB_SETFOREGROUND);
        LocalFree(argv);
        return 0;
    }

    g_AllowClientArgs = HasFlag(argc, argv, L"/allow_client_args");

    bool isService  = HasFlag(argc, argv, L"/service");
    bool isRegister = HasFlag(argc, argv, L"/register");
    bool isRemove   = HasFlag(argc, argv, L"/remove");

    if (isRegister || isService) {
        if (!parsedArgs.empty()) g_StaticArgs = parsedArgs;
    } else {
        if (!parsedArgs.empty()) g_ClientArgs = parsedArgs;
    }

    // 1. Service Control Manager Entry
    if (isService) {
        SERVICE_TABLE_ENTRYW table[] = {
            { const_cast<LPWSTR>(L""), ServiceMain },
            { nullptr, nullptr }
        };
        StartServiceCtrlDispatcherW(table);
        LocalFree(argv);
        return 0;
    }

    // 2. Registration Mode (Admin One-Time Setup)
    if (isRegister) {
        if (!IsElevated()) {
            SelfElevate();
            LocalFree(argv);
            return 0;
        }

        if (g_Target.empty()) {
            ShowError(L"Registration failed: /target=\"...\" parameter is required.", 0);
            LocalFree(argv);
            return 1;
        }

        if (g_User == L"administrator" && g_Domain == L".") {
            GetPrimaryAdminAccount(g_User, g_Domain);
        }

        std::wstring password;

        if (!parsedPass.empty()) {
            int choice = MessageBoxW(
                nullptr,
                L"SECURITY WARNING:\r\n\r\n"
                L"You have provided a password via '/reckless_password'.\r\n\r\n"
                L"Command-line parameters can be inspected by standard users via Task Manager or process monitoring tools.\r\n\r\n"
                L"Do you understand this risk and wish to continue?",
                L"Launch As - Critical Security Warning",
                MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND);

            if (choice != IDYES) {
                LocalFree(argv);
                return 1;
            }
            password = parsedPass;
        } else {
            if (!PromptForPassword(g_User, g_Domain, password)) {
                LocalFree(argv);
                return 1;
            }
        }

        HANDLE hTestToken = nullptr;
        if (!LogonUserW(g_User.c_str(), g_Domain.c_str(), password.c_str(),
                        LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hTestToken)) {
            DWORD err = GetLastError();
            SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
            ShowError((L"Registration failed: Invalid credentials for '" + g_Domain + L"\\" + g_User + L"'.").c_str(), err);
            LocalFree(argv);
            return 2;
        }
        CloseHandle(hTestToken);

        std::wstring credPath = GetAccountCredPath(g_Domain, g_User);
        bool saved = SaveEncrypted(credPath, password);
        SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));

        if (!saved) {
            ShowError(L"Failed to encrypt and store the credential.", GetLastError());
            LocalFree(argv);
            return 3;
        }

        DWORD err = InstallAndStartService();
        if (err != ERROR_SUCCESS) {
            ShowError(L"Failed to install or update the service.", err);
            LocalFree(argv);
            return 4;
        }

        std::wstring msg = L"Launch As Service (" + SanitizeIdentifier(g_Key) + L") is registered and running.\r\n\r\n"
                           L"Account: " + g_Domain + L"\\" + g_User + L"\r\n"
                           L"Target: " + g_Target + L"\r\n"
                           L"Static Args: " + (g_StaticArgs.empty() ? L"(none)" : g_StaticArgs) + L"\r\n"
                           L"Dynamic Client Args Allowed: " + (g_AllowClientArgs ? L"YES" : L"NO (Strict Mode)") + L"\r\n\r\n"
                           L"Standard users can launch this via:\r\n"
                           L"LaunchAs.exe /key=\"" + g_Key + L"\"\r\n\r\n"
                           L"--------------------------------------------------\r\n"
                           L"🎗️ Support the Author:\r\n"
                           L"This tool is free and open source. If this software saves\r\n"
                           L"you or your organization time, please consider supporting\r\n"
                           L"my cancer treatment fund:\r\n"
                           L"https://www.givesendgo.com/stalwart";

        MessageBoxW(nullptr, msg.c_str(), L"Launch As - Registration Complete", MB_ICONINFORMATION | MB_OK | MB_TOPMOST | MB_SETFOREGROUND);

        LocalFree(argv);
        return 0;
    }

    // 3. Removal Mode (Smart Credential Lifecycle)
    if (isRemove) {
        if (!IsElevated()) {
            SelfElevate();
            LocalFree(argv);
            return 0;
        }

        bool inUseByOthers = IsAccountUsedByOtherServices(g_Domain, g_User, g_Key);

        DWORD err = StopAndRemoveService();
        if (err != ERROR_SUCCESS) {
            ShowError(L"Failed to remove the service.", err);
            LocalFree(argv);
            return 4;
        }

        std::wstring credPath = GetAccountCredPath(g_Domain, g_User);
        std::wstring msg = L"Launch As Service (" + SanitizeIdentifier(g_Key) + L") has been removed.\r\n\r\n";

        if (!inUseByOthers) {
            DeleteFileW(credPath.c_str());
            msg += L"Account credential file was cleaned up (no other services depend on it).";
        } else {
            msg += L"Account credential file was preserved (other registered services depend on it).";
        }

        MessageBoxW(nullptr, msg.c_str(), L"Launch As", MB_ICONINFORMATION | MB_OK | MB_TOPMOST | MB_SETFOREGROUND);

        LocalFree(argv);
        return 0;
    }

    // 4. Default Mode: Run Client (Non-Admin Standard Use)
    int res = RunClient();
    LocalFree(argv);
    return res;
}
