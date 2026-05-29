#include "resource.h"
#include <string>
#include <cmath>
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <shlobj.h>
#include <mmdeviceapi.h>
#include <audiopolicy.h>
#include <tlhelp32.h>
#include <combaseapi.h>
#include <wbemidl.h>
#include <vector>
#include <mutex>
#include <algorithm>

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Gdi32.lib")

// --- Helpers ---

// RAII wrapper for COM pointers to avoid manual Release() chains.
template<typename T>
class ComPtr {
    T* ptr = nullptr;
public:
    ComPtr() = default;
    explicit ComPtr(T* p) : ptr(p) {}
    ~ComPtr() { if (ptr) ptr->Release(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    T** operator&() { return &ptr; }
    T* operator->() { return ptr; }
    T* Get() const { return ptr; }
    T* Detach() { T* p = ptr; ptr = nullptr; return p; }
    explicit operator bool() const { return ptr != nullptr; }
};

enum class RoleType { None = 0, App = 1, Voice = 2 };

// --- Application State ---
namespace AppState {
    constexpr int DefaultAppVolume = 20;
    constexpr int DefaultVoiceVolume = 100;

    float AppVolume = DefaultAppVolume / 100.0f;
    float VoiceVolume = DefaultVoiceVolume / 100.0f;
    HWND hwndSettings = NULL;

    std::vector<ISimpleAudioVolume*> AppSessions;
    std::vector<ISimpleAudioVolume*> VoiceSessions;
    std::mutex SessionsMutex;

    std::vector<ISimpleAudioVolume*>& GetSessionsForRole(RoleType role) {
        return (role == RoleType::App) ? AppSessions : VoiceSessions;
    }

    float* GetVolumeForRole(RoleType role) {
        return (role == RoleType::App) ? &AppVolume : &VoiceVolume;
    }

    void ApplyVolumeToSessions(RoleType role, float vol) {
        std::lock_guard<std::mutex> lock(SessionsMutex);
        for (ISimpleAudioVolume* pVol : GetSessionsForRole(role))
            pVol->SetMasterVolume(vol, NULL);
    }

    void AddSession(RoleType role, ISimpleAudioVolume* p) {
        std::lock_guard<std::mutex> lock(SessionsMutex);
        GetSessionsForRole(role).push_back(p);
    }

    void RemoveSession(RoleType role, ISimpleAudioVolume* p) {
        std::lock_guard<std::mutex> lock(SessionsMutex);
        auto& sessions = GetSessionsForRole(role);
        auto it = std::find(sessions.begin(), sessions.end(), p);
        if (it != sessions.end()) sessions.erase(it);
    }

    // --- Config Persistence (%APPDATA%\DiscordMixer\config.ini) ---

    std::wstring ConfigPath;

    void InitConfigPath() {
        WCHAR appData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData))) {
            ConfigPath = std::wstring(appData) + L"\\DiscordMixer";
            CreateDirectoryW(ConfigPath.c_str(), NULL);
            ConfigPath += L"\\config.ini";
        }
    }

    void LoadConfig() {
        if (ConfigPath.empty()) return;
        const wchar_t* section = L"Volume";
        AppVolume = GetPrivateProfileIntW(section, L"App", DefaultAppVolume, ConfigPath.c_str()) / 100.0f;
        VoiceVolume = GetPrivateProfileIntW(section, L"Voice", DefaultVoiceVolume, ConfigPath.c_str()) / 100.0f;
    }

    void SaveConfig() {
        if (ConfigPath.empty()) return;
        const wchar_t* section = L"Volume";
        WritePrivateProfileStringW(section, L"App", std::to_wstring((int)(AppVolume * 100.0f)).c_str(), ConfigPath.c_str());
        WritePrivateProfileStringW(section, L"Voice", std::to_wstring((int)(VoiceVolume * 100.0f)).c_str(), ConfigPath.c_str());
    }
}

// --- Process Identification ---

std::wstring GetProcessName(DWORD processId) {
    if (processId == 0) return L"[System Process]";

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return L"<Unknown>";

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == processId) {
                CloseHandle(hSnapshot);
                return pe.szExeFile;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return L"<Unknown>";
}

RoleType ClassifyDiscordProcess(DWORD processId) {
    ComPtr<IWbemLocator> pLoc;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pLoc));
    if (FAILED(hr)) return RoleType::None;

    ComPtr<IWbemServices> pSvc;
    BSTR bstrPath = SysAllocString(L"ROOT\\CIMV2");
    hr = pLoc->ConnectServer(bstrPath, NULL, NULL, 0, 0, 0, 0, &pSvc);
    SysFreeString(bstrPath);
    if (FAILED(hr)) return RoleType::None;

    hr = CoSetProxyBlanket(pSvc.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) return RoleType::None;

    WCHAR query[256];
    swprintf(query, 256, L"SELECT CommandLine FROM Win32_Process WHERE ProcessId = %lu", processId);
    BSTR bstrLang = SysAllocString(L"WQL");
    BSTR bstrQuery = SysAllocString(query);

    ComPtr<IEnumWbemClassObject> pEnum;
    hr = pSvc->ExecQuery(bstrLang, bstrQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnum);
    SysFreeString(bstrLang);
    SysFreeString(bstrQuery);
    if (FAILED(hr)) return RoleType::None;

    RoleType result = RoleType::None;
    IWbemClassObject* pObj = NULL;
    ULONG uReturn = 0;

    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn) == S_OK && uReturn > 0) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        if (SUCCEEDED(pObj->Get(L"CommandLine", 0, &vtProp, 0, 0))
            && vtProp.vt == VT_BSTR && vtProp.bstrVal) {
            std::wstring cmdLine = vtProp.bstrVal;
            if (cmdLine.find(L"--type=renderer") != std::wstring::npos)
                result = RoleType::Voice;
            else if (cmdLine.find(L"AudioService") != std::wstring::npos)
                result = RoleType::App;
        }
        VariantClear(&vtProp);
        pObj->Release();
    }

    return result;
}

// --- COM Event Listeners ---

class CAudioSessionEvents : public IAudioSessionEvents {
    LONG _cRef;
    ISimpleAudioVolume* _pVolumeControl;
    RoleType _role;

public:
    CAudioSessionEvents(ISimpleAudioVolume* pVol, RoleType role)
        : _cRef(1), _pVolumeControl(pVol), _role(role) {
        if (_pVolumeControl) {
            _pVolumeControl->AddRef();
            AppState::AddSession(_role, _pVolumeControl);
        }
    }

    ~CAudioSessionEvents() {
        if (_pVolumeControl) {
            AppState::RemoveSession(_role, _pVolumeControl);
            _pVolumeControl->Release();
        }
    }

    // IUnknown
    ULONG STDMETHODCALLTYPE AddRef() { return InterlockedIncrement(&_cRef); }
    ULONG STDMETHODCALLTYPE Release() {
        ULONG ref = InterlockedDecrement(&_cRef);
        if (ref == 0) delete this;
        return ref;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == __uuidof(IAudioSessionEvents)) {
            *ppv = static_cast<IAudioSessionEvents*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    // IAudioSessionEvents — only OnSimpleVolumeChanged does real work
    HRESULT STDMETHODCALLTYPE OnSimpleVolumeChanged(float NewVolume, BOOL, LPCGUID) {
        float target = *AppState::GetVolumeForRole(_role);
        if (std::abs(NewVolume - target) > 0.001f)
            _pVolumeControl->SetMasterVolume(target, NULL);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE OnDisplayNameChanged(LPCWSTR, LPCGUID) { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnIconPathChanged(LPCWSTR, LPCGUID) { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnChannelVolumeChanged(DWORD, float[], DWORD, LPCGUID) { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnGroupingParamChanged(LPCGUID, LPCGUID) { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnStateChanged(AudioSessionState) { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnSessionDisconnected(AudioSessionDisconnectReason) { return S_OK; }
};

void RegisterSessionIfTarget(IAudioSessionControl* pSessionControl) {
    ComPtr<IAudioSessionControl2> pCtrl2;
    DWORD processId = 0;

    if (FAILED(pSessionControl->QueryInterface(IID_PPV_ARGS(&pCtrl2))))
        return;
    pCtrl2->GetProcessId(&processId);

    if (GetProcessName(processId) != L"Discord.exe")
        return;

    RoleType role = ClassifyDiscordProcess(processId);
    if (role == RoleType::None)
        return;

    ComPtr<ISimpleAudioVolume> pVol;
    if (FAILED(pSessionControl->QueryInterface(IID_PPV_ARGS(&pVol))))
        return;

    float target = *AppState::GetVolumeForRole(role);
    float current = 0.0f;
    pVol->GetMasterVolume(&current);
    if (std::abs(current - target) > 0.001f)
        pVol->SetMasterVolume(target, NULL);

    CAudioSessionEvents* pEvents = new CAudioSessionEvents(pVol.Get(), role);
    pSessionControl->RegisterAudioSessionNotification(pEvents);
    pEvents->Release();
}

class CAudioSessionNotification : public IAudioSessionNotification {
    LONG _cRef;
public:
    CAudioSessionNotification() : _cRef(1) {}

    ULONG STDMETHODCALLTYPE AddRef() { return InterlockedIncrement(&_cRef); }
    ULONG STDMETHODCALLTYPE Release() {
        ULONG ref = InterlockedDecrement(&_cRef);
        if (ref == 0) delete this;
        return ref;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == __uuidof(IAudioSessionNotification)) {
            *ppv = static_cast<IAudioSessionNotification*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    HRESULT STDMETHODCALLTYPE OnSessionCreated(IAudioSessionControl* pNew) {
        if (pNew) RegisterSessionIfTarget(pNew);
        return S_OK;
    }
};

// --- Audio Initialization ---

HRESULT InitializeAudioHooking(IAudioSessionManager2** outMgr, CAudioSessionNotification** outNotif) {
    ComPtr<IMMDeviceEnumerator> pEnum;
    HRESULT hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL, IID_PPV_ARGS(&pEnum));
    if (FAILED(hr)) return hr;

    ComPtr<IMMDevice> pDevice;
    hr = pEnum->GetDefaultAudioEndpoint(eRender, eConsole, &pDevice);
    if (FAILED(hr)) return hr;

    ComPtr<IAudioSessionManager2> pMgr;
    hr = pDevice->Activate(__uuidof(IAudioSessionManager2), CLSCTX_ALL, NULL, (void**)&pMgr);
    if (FAILED(hr)) return hr;

    auto* pNotif = new CAudioSessionNotification();
    hr = pMgr->RegisterSessionNotification(pNotif);
    if (FAILED(hr)) {
        pNotif->Release();
        return hr;
    }

    // Scan existing sessions
    ComPtr<IAudioSessionEnumerator> pSessions;
    if (SUCCEEDED(pMgr->GetSessionEnumerator(&pSessions))) {
        int count = 0;
        pSessions->GetCount(&count);
        for (int i = 0; i < count; i++) {
            ComPtr<IAudioSessionControl> pCtrl;
            if (SUCCEEDED(pSessions->GetSession(i, &pCtrl)))
                RegisterSessionIfTarget(pCtrl.Get());
        }
    }

    *outMgr = pMgr.Detach();
    *outNotif = pNotif;
    return S_OK;
}

// --- User Interface ---

#define WM_TRAYICON (WM_USER + 1)
#define ID_SLIDER_APP   101
#define ID_SLIDER_VOICE 102

struct SliderDef {
    const wchar_t* label;
    int x;
    int controlId;
    float* volume;
    RoleType role;
};

static const SliderDef kSliders[] = {
    { L"App",   10, ID_SLIDER_APP,   &AppState::AppVolume,   RoleType::App   },
    { L"Voice", 80, ID_SLIDER_VOICE, &AppState::VoiceVolume, RoleType::Voice },
};

LRESULT CALLBACK SettingsProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            NONCLIENTMETRICSW ncm = { sizeof(NONCLIENTMETRICSW) };
            SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICSW), &ncm, 0);
            HFONT hFont = CreateFontIndirectW(&ncm.lfMessageFont);

            for (const auto& s : kSliders) {
                HWND hLbl = CreateWindowExW(0, L"STATIC", s.label,
                    WS_CHILD | WS_VISIBLE | SS_CENTER,
                    s.x, 10, 70, 15, hwnd, NULL, NULL, NULL);
                SendMessageW(hLbl, WM_SETFONT, (WPARAM)hFont, TRUE);

                HWND hSlider = CreateWindowExW(0, TRACKBAR_CLASSW, L"",
                    WS_CHILD | WS_VISIBLE | TBS_VERT | TBS_RIGHT,
                    s.x + 20, 30, 30, 120, hwnd, (HMENU)(INT_PTR)s.controlId, NULL, NULL);
                SendMessageW(hSlider, TBM_SETRANGE, TRUE, MAKELPARAM(0, 100));
                SendMessageW(hSlider, TBM_SETPOS, TRUE, (LPARAM)(100 - (*s.volume * 100.0f)));
            }
            break;
        }
        case WM_VSCROLL: {
            HWND hSlider = (HWND)lParam;
            if (!hSlider) break;
            int pos = SendMessageW(hSlider, TBM_GETPOS, 0, 0);
            float vol = (100 - pos) / 100.0f;

            for (const auto& s : kSliders) {
                if (GetDlgCtrlID(hSlider) == s.controlId) {
                    *s.volume = vol;
                    AppState::ApplyVolumeToSessions(s.role, vol);
                    AppState::SaveConfig();
                    break;
                }
            }
            break;
        }
        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            SetBkColor(hdcStatic, RGB(255, 255, 255));
            return (INT_PTR)GetStockObject(WHITE_BRUSH);
        }
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        default:
            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_TRAYICON:
            if (LOWORD(lParam) == WM_LBUTTONUP || LOWORD(lParam) == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                InsertMenuW(hMenu, 0, MF_BYPOSITION | MF_STRING, 1, L"Settings");
                InsertMenuW(hMenu, 1, MF_BYPOSITION | MF_STRING, 3, L"Source");
                InsertMenuW(hMenu, 2, MF_BYPOSITION | MF_STRING, 2, L"Exit");
                SetForegroundWindow(hwnd);
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);

                if (cmd == 1) {
                    ShowWindow(AppState::hwndSettings, SW_SHOW);
                    SetForegroundWindow(AppState::hwndSettings);
                } else if (cmd == 3) {
                    ShellExecuteW(NULL, L"open", L"https://github.com/katiras/DiscordMixer", NULL, NULL, SW_SHOWNORMAL);
                } else if (cmd == 2) {
                    PostQuitMessage(0);
                }
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

HWND RegisterAndCreateWindow(HINSTANCE hInst, const wchar_t* className, WNDPROC proc,
                              const wchar_t* title, DWORD style, DWORD exStyle,
                              int w, int h, HBRUSH bg = NULL) {
    WNDCLASSW wc = {};
    wc.lpfnWndProc = proc;
    wc.hInstance = hInst;
    wc.lpszClassName = className;
    wc.hbrBackground = bg;
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_APPICON));
    RegisterClassW(&wc);

    return CreateWindowExW(exStyle, className, title, style,
        CW_USEDEFAULT, CW_USEDEFAULT, w, h, NULL, NULL, hInst, NULL);
}

bool InitializeUI(HINSTANCE hInstance, NOTIFYICONDATAW& outNid) {
    AppState::hwndSettings = RegisterAndCreateWindow(
        hInstance, L"DiscordMixerSettingsClass", SettingsProc,
        L"DiscordMixer", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, WS_EX_APPWINDOW,
        180, 220, (HBRUSH)(COLOR_WINDOW + 1));

    HWND hwndTray = RegisterAndCreateWindow(
        hInstance, L"DiscordMixerTrayClass", WindowProc,
        L"Tray Window", 0, 0, 0, 0);

    if (!hwndTray) return false;

    outNid = {};
    outNid.cbSize = sizeof(NOTIFYICONDATAW);
    outNid.hWnd = hwndTray;
    outNid.uID = 1;
    outNid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    outNid.uCallbackMessage = WM_TRAYICON;
    outNid.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_APPICON));
    wcscpy_s(outNid.szTip, L"DiscordMixer");

    Shell_NotifyIconW(NIM_ADD, &outNid);
    return true;
}

// --- Entry Point ---

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int) {
    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_BAR_CLASSES };
    InitCommonControlsEx(&icex);

    AppState::InitConfigPath();
    AppState::LoadConfig();

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return -1;

    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    NOTIFYICONDATAW nid = {};
    if (!InitializeUI(hInstance, nid)) {
        CoUninitialize();
        return -1;
    }

    IAudioSessionManager2* pSessionManager = NULL;
    CAudioSessionNotification* pSessionNotification = NULL;
    InitializeAudioHooking(&pSessionManager, &pSessionNotification);

    MSG msg = {};
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Cleanup
    if (pSessionManager && pSessionNotification)
        pSessionManager->UnregisterSessionNotification(pSessionNotification);
    if (pSessionNotification) pSessionNotification->Release();
    if (pSessionManager) pSessionManager->Release();

    Shell_NotifyIconW(NIM_DELETE, &nid);
    CoUninitialize();
    return 0;
}
