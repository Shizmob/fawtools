#!/usr/bin/env python3
import struct

class LFSR:
	def __init__(self, seed: int, mask: int, rot: int) -> None:
		self.value = seed
		self.mask = mask
		self.rot = rot

	def peek(self) -> int:
		return self.value & 1

	def next(self) -> int:
		if self.peek():
			self.value ^= self.mask
			self.value >>= 1
			self.value |= (~self.rot & 0xFFFFFFFF)
			return True
		else:
			self.value >>= 1
			self.value &= self.rot
			return False

class Crypter:
	def __init__(self, key: bytes) -> None:
		a, b, c = struct.unpack('<III', key)

		self.a = LFSR(a or 0x13579bdf, 0x80000062, 0x7FFFFFFF)
		self.b = LFSR(b or 0x2468ace0, 0x40000020, 0x3FFFFFFF)
		self.c = LFSR(c or 0xFDB97531, 0x10000002, 0x0FFFFFFF)

	def next(self, n: int) -> int:
		v = 0
		b = self.b.peek()
		c = self.c.peek()

		for _ in range(n):
			if self.a.next():
				b = self.b.next()
			else:
				c = self.c.next()
			v <<= 1
			v |= b ^ c

		return v

	def crypt_block(self, block: int):
		return block ^ self.next(8)

	def crypt(self, block: bytes) -> bytes:
		return bytes(self.crypt_block(x) for x in block)

MAGIC = b'Encrypted program file.\r\n2\x00\x00'

if __name__ == '__main__':
	import sys, os

	if len(sys.argv) < 3:
		print('usage: {} INFILE OUTFILE'.format(sys.argv[0]), file=sys.stderr)
		sys.exit(255)

	with open(sys.argv[1], 'rb') as f:
		fw = f.read()

	if fw.startswith(MAGIC):
		print('Decrypting')
		c = Crypter(fw[80:92])
		key = c.crypt(fw[92:104])

		c = Crypter(key)
		fw = c.crypt(fw[104:])
	else:
		print('Encrypting')
		key = os.urandom(12)
		fw = Crypter(key).crypt(fw)

		kek = bytes(12)
		hdr = MAGIC
		hdr += os.urandom(76 - len(hdr))
		hdr += bytes(4)
		hdr += kek
		hdr += Crypter(kek).crypt(key)
		fw = hdr + fw

	with open(sys.argv[2], 'wb') as f:
		f.write(fw)
