bits 32

extern WinHttpOpen
extern WinHttpConnect
extern WinHttpOpenRequest
extern WinHttpSendRequest
extern WinHttpReceiveResponse
extern WinHttpReadData
extern WinHttpCloseHandle
extern CreateFileA
extern WriteFile
extern CloseHandle
extern ExitProcess

section .data
userAgent dw 'M','y','D','l','r',0
serverName dw 'e','x','a','m','p','l','e','.','c','o','m',0
filePath dw '/','f','i','l','e','.','t','x','t',0
httpVerb dw 'G','E','T',0
localFile db 'downloaded.bin',0
buffer times 1024 db 0

section .bss
hSession   resd 1
hConnect   resd 1
hRequest   resd 1
bytesRead resd 1
bytesWrit resd 1
hFile      resd 1

section .text
global _start

_start:
    ; WinHttpOpen
    push 0
    push 0
    push 0
    push 0
    push userAgent
    call WinHttpOpen
    mov [hSession], eax

    ; WinHttpConnect
    push 80
    push serverName
    push [hSession]
    call WinHttpConnect
    mov [hConnect], eax

    ; WinHttpOpenRequest
    push 0
    push 0
    push filePath
    push httpVerb
    push [hConnect]
    call WinHttpOpenRequest
    mov [hRequest], eax

    ; WinHttpSendRequest
    push 0
    push 0
    push 0
    push 0
    push [hRequest]
    call WinHttpSendRequest

    ; WinHttpReceiveResponse
    push 0
    push [hRequest]
    call WinHttpReceiveResponse

    ; CreateFileA
    push 0
    push 0
    push 2              ; CREATE_ALWAYS
    push 0
    push 0
    push 0x40000000     ; GENERIC_WRITE
    push localFile
    call CreateFileA
    mov [hFile], eax

.read:
    push bytesRead
    push 1024
    push buffer
    push [hRequest]
    call WinHttpReadData

    mov eax, [bytesRead]
    test eax, eax
    jz .done

    push 0
    push bytesWrit
    push eax
    push buffer
    push [hFile]
    call WriteFile
    jmp .read

.done:
    push [hFile]
    call CloseHandle
    push [hRequest]
    call WinHttpCloseHandle
    push [hConnect]
    call WinHttpCloseHandle
    push [hSession]
    call WinHttpCloseHandle
    push 0
    call ExitProcess
