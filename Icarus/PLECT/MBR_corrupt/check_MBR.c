#include <windows.h>
#include <stdio.h>
#include <winioctl.h>


__declspec(dllexport) int Star_bizzard(){

    HANDLE hDisk = CreateFileA(
        "\\\\.\\PhysicalDrive0",       // Disk 0 (system disk)
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDisk == INVALID_HANDLE_VALUE) {
        return 1;
    }

    PARTITION_INFORMATION_EX pinfo;
    DWORD bytesReturned;

    if (!DeviceIoControl(
        hDisk,
        IOCTL_DISK_GET_PARTITION_INFO_EX,
        NULL,
        0,
        &pinfo,
        sizeof(pinfo),
        &bytesReturned,
        NULL
    )) {
        CloseHandle(hDisk);
        return 1;
    }
    int style;
    switch (pinfo.PartitionStyle) {
        case PARTITION_STYLE_MBR:
            style = 2;
            break;
        case PARTITION_STYLE_GPT:
            style = 3;
            break;
        default:
            style = 4;
            break;
    }
    
    CloseHandle(hDisk);
    return style;
}