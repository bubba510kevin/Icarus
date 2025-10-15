; =========================================================
; Bare-Metal UEFI File Downloader
; Full x86-64 Assembly
; Ready to assemble with NASM
; =========================================================

BITS 64
DEFAULT REL

SECTION .data
align 16

; MMIO Base for e1000 NIC
e1000_mmio:      dq 0xF0000000

; TX/RX Descriptor Rings
align 16
tx_desc_ring:    resb 8*16
rx_desc_ring:    resb 8*16

tx_head:         dq 0
tx_tail:         dq 0
rx_head:         dq 0
rx_tail:         dq 0

; TX/RX Buffers
align 16
tx_buffers:      resb 8*2048
rx_buffers:      resb 8*2048

; MAC/IP
align 16
src_mac:         db 0x52,0x54,0x00,0x12,0x34,0x56
server_mac:      resb 6
src_ip:          dd 0xC0A80164        ; 192.168.1.100
server_ip:       dd 0xC0A801C8        ; 192.168.1.200

tx_frame:        resb 2048
rx_frame:        resb 2048

; Ethernet / ARP
ETH_TYPE_ARP:    dw 0x0806
ETH_TYPE_IP:     dw 0x0800
ARP_HW_TYPE:     dw 0x0001
ARP_PROTO_TYPE:  dw 0x0800
ARP_HW_LEN:      db 6
ARP_PROTO_LEN:   db 4
ARP_OP_REQUEST:  dw 0x0001
ARP_OP_REPLY:    dw 0x0002

; UDP Ports
UDP_SRC_PORT:    dw 12345
UDP_DST_PORT:    dw 12345

; File Transfer Buffers
align 16
file_buffers:       resb 65536*4
rx_temp_buffer:     resb 65536
tx_temp_buffer:     resb 65536
current_buffer_idx: dq 0
total_buffers:      dq 4
bytes_received_total:dq 0
file_size_bytes:    dq 262144         ; example 256 KB
seq_number_file:    dq 0
filename_request:   db 'file.bin',0

; UEFI File Handles
uefi_file_handle:   dq 0
uefi_fs_handle:     dq 0

align 16
filename_uefi:      resw 256

SECTION .text
global start

; =========================================================
; Entry point
; =========================================================
start:
    call nic_init_full         ; initialize NIC
    call send_arp_request      ; broadcast ARP
    call receive_arp_reply     ; get server MAC
    call download_file_full    ; download file via UDP
    hlt                        ; finished

; =========================================================
; NIC Initialization
; =========================================================
nic_init_full:
    lea rdi,[tx_desc_ring]
    xor rcx,rcx
.nic_tx_loop:
    lea rbx,[tx_buffers + rcx*2048]
    mov qword [rdi+0], rbx
    mov dword [rdi+8],2048
    mov dword [rdi+12],0
    add rdi,16
    inc rcx
    cmp rcx,8
    jl .nic_tx_loop
    mov qword [tx_head],0
    mov qword [tx_tail],0

    lea rdi,[rx_desc_ring]
    xor rcx,rcx
.nic_rx_loop:
    lea rbx,[rx_buffers + rcx*2048]
    mov qword [rdi+0], rbx
    mov dword [rdi+8],2048
    mov dword [rdi+12],0
    add rdi,16
    inc rcx
    cmp rcx,8
    jl .nic_rx_loop
    mov qword [rx_head],0
    mov qword [rx_tail],0

    ; Enable TX/RX
    mov rax,[e1000_mmio]
    add rax,0x004
    mov edx,0x00002008
    mov [rax],edx

    mov rax,[e1000_mmio]
    add rax,0x010
    mov edx,0x00000002
    mov [rax],edx

    ; Set TDT/RDT
    mov rax,[e1000_mmio]
    add rax,0x038
    mov edx,0
    mov [rax],edx
    mov rax,[e1000_mmio]
    add rax,0x028
    mov edx,7
    mov [rax],edx
    ret

; =========================================================
; Delay Loop
; =========================================================
delay_loop_full:
    mov rcx,100000
.delay_loop:
    nop
    loop .delay_loop
    ret

; =========================================================
; Send Ethernet Frame
; RCX = length, RDX = buffer
; =========================================================
send_ethernet_frame:
    mov rax,[tx_tail]
    mov rcx,rax
    lea rdi,[tx_desc_ring + rcx*16]
.wait_tx:
    mov eax,[rdi+12]
    test al,1
    jnz .desc_free
    call delay_loop_full
    jmp .wait_tx
.desc_free:
    mov rbx,[rdi]
    mov r8,rdx
.copy_loop:
    cmp r8,0
    je .copy_done
    mov al,[rsi]
    mov [rbx],al
    inc rsi
    inc rbx
    dec r8
    jmp .copy_loop
.copy_done:
    mov dword [rdi+8],edx
    mov dword [rdi+12],0x9
    inc rcx
    cmp rcx,8
    jb .update_tail
    xor rcx,rcx
.update_tail:
    mov [tx_tail],rcx
    mov rax,[e1000_mmio]
    add rax,0x038
    mov [rax],ecx
    ret

; =========================================================
; Receive Ethernet Frame
; Returns RAX = length
; =========================================================
receive_ethernet_frame:
    mov rax,[rx_tail]
    mov rcx,rax
    lea rdi,[rx_desc_ring + rcx*16]
.wait_rx:
    mov edx,[rdi+12]
    test dl,1
    jz .wait_rx
    mov rbx,[rdi]
    mov r8d,[rdi+8]
    lea rdi,[rx_temp_buffer]
.copy_loop_rx:
    cmp r8d,0
    je .done_rx
    mov al,[rbx]
    mov [rdi],al
    inc rbx
    inc rdi
    dec r8d
    jmp .copy_loop_rx
.done_rx:
    mov dword [rx_desc_ring + rcx*16 +12],0
    inc rcx
    cmp rcx,8
    jb .update_rx_tail
    xor rcx,rcx
.update_rx_tail:
    mov [rx_tail],rcx
    mov rax,[e1000_mmio]
    add rax,0x028
    mov [rax],rcx
    ret

receive_network_packet_full:
    call receive_ethernet_frame
    ret

; =========================================================
; ASCII -> UTF16
; =========================================================
ascii_to_uefi_char16:
    xor rcx,rcx
.convert_loop:
    mov al,[rsi+rcx]
    mov word [rdi+rcx*2],ax
    inc rcx
    test al,al
    jnz .convert_loop
    ret

; =========================================================
; UEFI Open File
; RCX=FS handle, RDX=UTF16 filename, R8=open mode, R9=attributes
; Returns RAX=file handle
; =========================================================
open_file_uefi:
    mov rax,[rcx]  ; vtable Open
    call rax
    ret

; =========================================================
; UEFI Write File
; RCX=file handle, RDX=buffer, R8=size
; =========================================================
write_file_efi:
    mov rsi,rdx
    mov rdx,r8
    mov rdi,rcx
    mov rax,[rdi]  ; vtable Write
    call rax
    ret

; =========================================================
; UEFI File Write Helper
; =========================================================
write_file_uefi:
    mov rax,[uefi_file_handle]
    test rax,rax
    jnz .file_opened
    lea rsi,[filename_request]
    lea rdi,[filename_uefi]
    call ascii_to_uefi_char16
    mov rcx,[uefi_fs_handle]
    lea rdx,[filename_uefi]
    mov r8,0x07
    mov r9,0
    call open_file_uefi
    mov [uefi_file_handle],rax
.file_opened:
    mov rcx,[uefi_file_handle]
    mov rdx,rsi
    mov r8,rdx
    call write_file_efi
    ret

; =========================================================
; ARP Request / Reply
; =========================================================
send_arp_request:
    lea rdi,[tx_temp_buffer]
    mov byte [rdi+0],0xFF
    mov byte [rdi+1],0xFF
    mov byte [rdi+2],0xFF
    mov byte [rdi+3],0xFF
    mov byte [rdi+4],0xFF
    mov byte [rdi+5],0xFF
    mov rsi,src_mac
    lea rbx,[rdi+6]
    mov rcx,6
.copy_src_mac:
    mov al,[rsi]
    mov [rbx],al
    inc rsi
    inc rbx
    loop .copy_src_mac
    mov word [rdi+12],ETH_TYPE_ARP
    ; ARP payload
    lea rsi,[tx_temp_buffer+14]
    mov word [rsi+0],ARP_HW_TYPE
    mov word [rsi+2],ARP_PROTO_TYPE
    mov byte [rsi+4],ARP_HW_LEN
    mov byte [rsi+5],ARP_PROTO_LEN
    mov word [rsi+6],ARP_OP_REQUEST
    mov rsi,src_mac
    lea rdi,[tx_temp_buffer+14+8]
    mov rcx,6
.copy_sender_mac:
    mov al,[rsi]
    mov [rdi],al
    inc rsi
    inc rdi
    loop .copy_sender_mac
    mov eax,[src_ip]
    mov [rdi],eax
    add rdi,4
    xor rax,rax
    mov [rdi],rax
    add rdi,6
    mov eax,[server_ip]
    mov [rdi],eax
    add rdi,4
    mov rdx,42
    call send_ethernet_frame
    ret

receive_arp_reply:
    call receive_ethernet_frame
    lea rsi,[rx_temp_buffer+22]
    lea rdi,[server_mac]
    mov rcx,6
.copy_server_mac:
    mov al,[rsi]
    mov [rdi],al
    inc rsi
    inc rdi
    loop .copy_server_mac
    ret

; =========================================================
; IP Header
; =========================================================
build_ip_header:
    lea rdi,[tx_temp_buffer + 14]
    mov byte [rdi+0],0x45
    mov byte [rdi+1],0x00
    mov rax,rdx
    add rax,28
    mov word [rdi+2],ax
    mov word [rdi+4],0x0000
    mov word [rdi+6],0x4000
    mov byte [rdi+8],64
    mov byte [rdi+9],17
    mov word [rdi+10],0x0000
    mov eax,[src_ip]
    mov [rdi+12],eax
    mov eax,[server_ip]
    mov [rdi+16],eax
    call checksum_ip_dynamic
    mov [rdi+10],ax
    ret

checksum_ip_dynamic:
    lea rsi,[tx_temp_buffer + 14]
    xor eax,eax
    mov ecx,10
.ip_sum_loop:
    mov dx,[rsi]
    add ax,dx
    adc ax,0
    add rsi,2
    loop .ip_sum_loop
    mov dx,ax
    shr dx,16
    add ax,dx
    not ax
    ret

; =========================================================
; UDP Header
; =========================================================
build_udp_header:
    lea rdi,[tx_temp_buffer + 14 + 20]
    mov word [rdi+0],UDP_SRC_PORT
    mov word [rdi+2],UDP_DST_PORT
    mov rax,rdx
    add rax,8
    mov word [rdi+4],ax
    mov word [rdi+6],0
    ret

; =========================================================
; File Chunk Processing
; =========================================================
process_file_chunk_full:
    mov rax,[current_buffer_idx]
    imul rax,65536
    lea rdi,[file_buffers + rax]
    mov rcx,rdx
.chunk_loop:
    cmp rcx,0
    je .done
    mov al,[rsi]
    mov [rdi],al
    inc rsi
    inc rdi
    dec rcx
    jmp .chunk_loop
.done:
    add qword [bytes_received_total],rdx
    inc qword [current_buffer_idx]
    cmp qword [current_buffer_idx],[total_buffers]
    jb .skip_reset
    mov qword [current_buffer_idx],0
.skip_reset:
    ret

; =========================================================
; Send File Request
; =========================================================
send_file_request_full:
    lea rdi,[tx_temp_buffer]
    xor rcx,rcx
.copy_filename:
    lodsb
    stosb
    test al,al
    jnz .copy_filename
    mov rax,[seq_number_file]
    mov [rdi],rax
    add rdi,8
    lea rsi,[tx_temp_buffer]
    sub rdi,rsi
    mov rdx,rdi
    call build_ip_header
    call build_udp_header
    call send_ethernet_frame
    ret

; =========================================================
; Download File
; =========================================================
download_file_full:
    xor rax,rax
    mov [bytes_received_total],rax
    xor rax,rax
    mov [current_buffer_idx],rax
.download_outer:
    cmp [bytes_received_total],[file_size_bytes]
    jae .download_done
    lea rsi,[filename_request]
    call send_file_request_full
    call receive_network_packet_full
    mov rdx,rax
    lea rsi,[rx_temp_buffer]
    call process_file_chunk_full
    lea rsi,[file_buffers]
    mov rax,[current_buffer_idx]
    imul rax,65536
    add rsi,rax
    mov rcx,rdx
    call write_file_uefi
    jmp .download_outer

.download_done:
    ret

