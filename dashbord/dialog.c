#define COBJMACROS
#include <windows.h>
#include <commdlg.h>
#include <shobjidl.h>
#include <stdlib.h>

__declspec(dllexport)
BOOL DialogBoxFUN(LPCSTR lptext, LPCSTR lpcap)
{
    MessageBoxA(NULL, lptext, lpcap, MB_OK | MB_ICONINFORMATION);
    return TRUE;
}


__declspec(dllexport)
char *filediolog(){
    OPENFILENAMEA ofn;
    char fileName[MAX_PATH] = {0};
    char folderName[MAX_PATH] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = fileName;
    
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "All Files\0*.*\0Text Files\0*.txt\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn)) {
        return fileName;
    } else {
        DWORD err = CommDlgExtendedError();
        if (err != 0) {
            MessageBoxA(NULL, "Dialog error", "Error", MB_ICONERROR);
            return "-1";
        }
    }
    return "1";
}

__declspec(dllexport)
char *folderdiolog(){
    OPENFILENAMEA ofn;
    char fileName[MAX_PATH] = {0};
    char folderName[MAX_PATH] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = fileName;
    
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "All Files\0*.*\0Text Files\0*.txt\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn)) {
        return fileName;
    } else {
        DWORD err = CommDlgExtendedError();
        if (err != 0) {
            MessageBoxA(NULL, "Dialog error", "Error", MB_ICONERROR);
            return "-1";
        }
    }
    return "1";
}

char* folderdialog(void)
{
    HRESULT hr;
    IFileOpenDialog* dialog = NULL;
    IShellItem* item = NULL;
    PWSTR widePath = NULL;
    char* ansiPath = NULL;

    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
        return NULL;

    hr = CoCreateInstance(
        &CLSID_FileOpenDialog,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_IFileOpenDialog,
        (void**)&dialog
    );

    if (SUCCEEDED(hr))
    {
        DWORD options;
        IFileOpenDialog_GetOptions(dialog, &options);
        IFileOpenDialog_SetOptions(
            dialog,
            options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM
        );

        if (SUCCEEDED(IFileOpenDialog_Show(dialog, NULL)))
        {
            if (SUCCEEDED(IFileOpenDialog_GetResult(dialog, &item)))
            {
                if (SUCCEEDED(IShellItem_GetDisplayName(
                    item,
                    SIGDN_FILESYSPATH,
                    &widePath)))
                {
                    int size = WideCharToMultiByte(
                        CP_ACP, 0, widePath, -1, NULL, 0, NULL, NULL
                    );

                    ansiPath = (char*)malloc(size);
                    if (ansiPath)
                    {
                        WideCharToMultiByte(
                            CP_ACP, 0, widePath, -1, ansiPath, size, NULL, NULL
                        );
                    }

                    CoTaskMemFree(widePath);
                }
                IShellItem_Release(item);
            }
        }
        IFileOpenDialog_Release(dialog);
    }

    CoUninitialize();
    return ansiPath; // caller must free()
}