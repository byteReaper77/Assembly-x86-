Reverse Shell in Assembly (Linux x86)
Description:
This project is a 32-bit Linux reverse shell written in Assembly (NASM syntax). It is designed to establish a reverse shell from a victim machine to an attacker's machine over either TCP or ICMP. The shell includes mechanisms for creating persistence by adding a hidden process and ensuring that it survives system restarts.

Features:
Reverse shell using TCP or ICMP protocols.

Persistence mechanism that creates a hidden process on the victim machine.

Encrypted IP address for stealth communication.

Executes commands on the victim's machine via a shell.

Prerequisites:
To compile and run the reverse shell, you need:

NASM (Netwide Assembler) to compile the Assembly code.

LD (Linker) to link the object file and create the executable.

A machine running Linux 32-bit.

Compilation:
Install NASM if you don't have it already:

sudo apt-get install nasm
Compile the Assembly code:

nasm -f elf shell.asm -o shell.o
ld -m elf_i386 shell.o -o shell

Usage:
1. Setup the Listener on the attacker's machine:
First, you need to set up a listener on the attacker's machine to catch the reverse shell connection:

nc -lvnp 50129
This will listen on port 50129 for incoming connections.

2. Execute the Binary on the victim's machine:
Once you have compiled the shell, execute the binary on the victim's machine. The reverse shell will attempt to connect back to the attacker's machine on the specified port (50129). If the TCP connection fails, it will attempt to use ICMP as a fallback.

Legal and Ethical Warning:
This code is for educational purposes only. Using this code to compromise, attack, or gain unauthorized access to any system is illegal and unethical. It is important to only use this in controlled environments such as penetration testing labs or with explicit permission from the owner of the system.

The author is not responsible for any damage, loss, or legal consequences resulting from the misuse of this software.

Persistence and Hiding Mechanism:
This shell code includes a persistence mechanism where:

A hidden process is created and added to the /etc/hostname file (or another file, depending on configuration).

It adds an entry to the victim's .bashrc file to run the shell every time the user logs in.

The shell also hides the binary by placing it in /dev/shm/.hidden_binary, making it less likely to be detected by regular file searches.

Modifications:
If you'd like to modify the shell (for example, to change the listening port or the encrypted IP address), you can modify the relevant values in the source code. The IP address and port are encrypted in the code to prevent easy detection.

License:
This project is not licensed for illegal or malicious use. Please refer to the LICENSE file for more information.