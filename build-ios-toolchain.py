#!/usr/bin/env python

from __future__ import with_statement

DMG_URL = 'https://developer.apple.com/downloads/download.action'
DMG_PATH = "Developer_Tools/xcode_4.6.3/xcode4630916281a.dmg"
DMG_KOLY_SHA1 = "f21001cc2b7eb230003250945156b1b6354ccd77"

import os
import sys
import time
import logging
import re
import hashlib
import struct
import binascii
import bisect
import operator
import zlib
from xml.etree import ElementTree
from getpass import getpass

logging.getLogger().setLevel(logging.DEBUG)

try: # Python 3
	from urllib.request import build_opener, HTTPRedirectHandler, HTTPCookieProcessor
	from urllib.parse import urlencode
except ImportError: # Python 2
	from urllib2 import build_opener, HTTPRedirectHandler, HTTPCookieProcessor
	from urllib import urlencode
	input = raw_input
	range = xrange
	bytes = str
	str = unicode
	chr = unichr

try:
	next
except NameError: # Python 2.5
	next = lambda x: x.next()

lower_case_table = list(struct.unpack('>2816H', zlib.decompress(binascii.a2b_base64(
"""
eNrt11PwmEuTB+Ce/0zHmNhJd2yc2LZtJyc+sW3b1olt27Zt2+red8+ytr5afLU3W7X93M3Ub6qr
pm/aQAgAWHCA8LcqFPznFRrCwP/X/80KC+FAFUwwAv80AKH++s5/PA4PESAiRILI4CEKRIVoEB1i
QEyIBbEhDsSFeBAfEkBCSAQEDIkhCSSFZJAcUkBKSAWpIQ2khXSQHjJARsgEv0FmyAJZIRtkhxyQ
E3JBbsgDeSEf5IcC0BAaQWNoAk3hd2gGzaEFtIRW0BrawB/QFtpBe+gAHaETdIYu0BW6QXfoAbWh
DtSFelAfGvxd+Z7QC3pDH+gL/aA/DICBMAgGwxAYCsNgOIyAkTAKRsMYGAvjYDxMgIkwCSbDFJgK
02A6zICZMAtmwxyYC/NgPiyAhfAnLILFsASWwjJYDitgJayC1bAG1sI6WA8bYCNsgs2wBbbCNtgO
O2An7ILdsAf2wj7YDwfgIByCx3AEjsIxOA4n4CScgtNwBt7COTgPF+AiXILLcAW+wjW4DjfgJtwC
gTtwF+7BfXgAD+FRkH8CT+EZPIcX8BJewWt4E+TfwXv4AB/hE3yGL0H+G3yHH/ATfgV5NWCMCTHW
OIMmlAltwpiwJpwJbyKYiCaSiWyiBKKaaCa6iWFimlgmtolj4pp4Jr5JYBKaRIYMm8QmiUlqkpkU
gZQmlUlt0pi0Jp1JbzKYjCaTyRzIYrKabCa7yWFymlwmt8lj8pp8pkCgUKCwKWKKmmKmuClhSprS
gTKmrClnypsKpqKpHKhiqppqprqpYWqaWqa2qWPqmnqmvmlgGppGprFpYpqaZoHmpoVpaVqZ1qaN
+cO0Ne1Me9PBdDSdTGfTxXQ13Ux308P0NL1Mb9PH9DX9QiqbgYHBZnBIFTPMDAupFlLdjAqMNrdC
aobUNhPMhJAGIY3N5JAWIc3N9MAMMzOkbUgHMyeks5ln5puFgUWBxWapWRoy0Cw3K8wqsypkmFlj
1oaMCBlpNgY2m80hE8y2wHazw+wK7DZ7zF6zz+w3B8zhvxz7y8m/nDKnzRlz1pwz580Fc9FcMpfN
FXPVXDPXzQ1z09wyt80dc9fcM/fNA/Mo8Ng8MU/NM/PcvDAvzSvz2rwxb82Hv3w0n8xn88V8Nd/M
d/PD/DS/jBi1YI0NsdY6izaUDW3D2LA2nA1vI9iINpKNbL2NYqPaaDa6jWFj2lg2to1j49p4Nr5N
YBPaRJYs28Q2iU1qk9nkNoVNaVPZ1DaNTWvT2fQ2g81oM9nfbGabxWa12Wx2m8PmtLlsbpvH5rX5
bH5bwBa0hWxhW8QWtcVscVvClrSlbGlbxpa15Wx5W8FWtJVsZVvFVrXVbHVbw9a0tWxtW8fWtfVs
fdvANrSNbGPbxDa1v9tmtrltYVvaVra1bWP/sG1tO9vedrAdbSfb2XaxXW032932sD1tL9vb9rF9
bT/b3w6wA+0gO9gOsUPtMDvcjrAj7Sg72o6xY+04u86utxvsRrvJbrZb7Fa7zW63O+xOu8vutnvs
XrvPLrAH7EF7yB62R+xRe8wutyvsSrvKrrZr7Nr/Rn7/f8gftyfsSXvKnrZn7Fl7zp63F+xFe8le
tlfsVXvNXrc37E17y962d+xde88+CDwKPAk8C7wIvAq8Cby17+x7+8F+tJ/sZ/vFfrXf7Hf7w/60
v6xYdeCMq+Ssq+KqumoutKvharparraL4CK6SK6+y+gyud9cZpfFZXXZXHaXw8VxuVxul8fldflc
flfAFXSFXGFXxBV1xVxxV8KVdKVcaVfGlXXlXPm/kc/5P8pXcBWD/ir/c3/V/7W/Oq6uqxf01zDQ
ONA00CzQItAq0CbQNtA+0DHQOdDFdXXdAz0DvQN9A/0DA9xAN8gNdkPcUDfMDXcj3Eg3yo12Y9xY
Nz4wMTA5MDUwPTAzMDswNzA/sDCwKLAksCywIrAqsCawLrAhsCmwJbAtsCOwK7AnsNftc/vdwcAh
d9gdDRxzx93JwCl32p1xZ905d95dcBfdJXfZXXFX3TV33d1wN90td9vdcXfdPXffPXAP3SP32D1x
T90z99y9cC/dK/favXFv3Tv33n1wH90n99l9cV/dN/fd/XA/3S8nThHQYAhadIgYCkNjGAyL4TA8
RsCIGAkjo8coGBWjYXSMgTExFsbGOBgX42F8TIAJMRESMibGJJgUk2FyTIEpMRWmxjSYFtNhesyA
GbEhNsLG2ASb4u/YDJtjC2yJrbA1tsE/sC22w/bYATtiJ+yMXbArdsPu2AN7Yi/sjX2wL/bD/jgA
B+IgHIxDsDrWwJpYC2tjHayL9bA+NvhffX8oDsPhOAJH4igcjWNwLI7D8TgBJ+IknIxTcCpOw+k4
A2fiLJyNc3AuzsP5uAAX4p+4CBfjElyKy3A5rsCVuApX4xpci+twPW7AjbgJN+MW3IrbcDvuwJ24
C3fjHtyL+3A/HsCDeAgP4xE8isfwOJ7Ak3gKT+MZPIvn8DxewIt4CS/jFbyK1/A63sCbeAtv4x28
i/fwPj7Ah/gIH+MTfIrP8Dm+wJf4Cl/jG3yL7/A9fsCP+Ak/4xf8it/wO/7An/gLBdWDNz7EW+88
+lA+tA/jw/pwPryP4CP6SD6y9z6Kj+qj+eg+ho/pY/nYPo6P6+P5+D6BT+gTefLsE/skPqlP5pP7
FD6lT+VT+zQ+rU/n0/sMPqPP5H/zmX0Wn9Vn89l9Dp/T5/K5fR6f1+fz+X0BX9AX8oV9EV/UF/PF
fQlf0pfypX0ZX9aX8+V9BV/RV/KVfRVf1Vfz1X0NX9PX8rV9HV/X1/P1fQPf0DfyjX0T39T/7pv5
5r6Fb+lb+da+jf/Dt/XtfHvfwXf0nXxn38V39d18d9/D9/S9fG/fx/f1/Xx/P8AP9IP8YD/ED/XD
/HA/wo/0o/xoP8aP9eP8eD/BT/ST/GQ/xU/10/x0P8PP9LP8bD/Hz/Vn/Tl/3l/wF/0lf9lf8Vf9
NX/d3/A3/S1/29/xd/09f98/8A/9I//YP/FP/TP/3L/wL/0r/9q/8W/9O//ef/Af/Sd/2B/xR/0x
f9yf8Cf9KX/an/lfff+z/+K/+m/+u//hf/pfXrwSkKEQsuQIKRSFpjAUlsJR+H/ZEchTFIpK0Sg6
xaCYFItiUxyKS/EoPiWghJSIiJgSUxJKSskoOaWglJTq3zYMykAZKRP9RpkpC2WlbJSdclBOykW5
KQ/lpXyUnwpQQSpEhakIFaViVJxKUEkqRaWpDJWlclSeKlBFqkSVqQpVpWpUnWpQTapFtakO1aV6
VJ8aUENqRI2pCTWl36kZNacW/37HoXbUnjpQR+pEnakLdaVu1J16UE/qRb2pD/WlftSfBtBAGkSD
aQgNpWE0nEbQSBpFo2kMjaVxNJ4m0ESaRJNpCk2laTSdZtBMmkWzaQ7NpXk0nxbQQvqTFtFiWkJL
aRktpxW0klbRalpDa2kdracNtJE20WbaQltpG22nHbSTdtFu2kN7aR/tpwN0kA7RYTpCR+kYHacT
dJJO0Wk6Q2fpHJ2nC3SRLtFlukJX6Rpdpxt0k27RbbpDd+ke3acH9JAe0WN6Qk/pGT2nF/SSXtFr
ekNv6R29pw/0kT7RZ/pCX+kbfacf9JN+kZAysOEQtuwYORSH5jAclsNxeI7AETkSR2bPUTgqR+Po
HINjciyOzXE4Lsfj+JyAE3IiJmZOzEk4KSfj5JyCU3IqTs1pOC2n4/ScgTNyJv6NM3MWzsrZODvn
4Jyci3NzHs7L+Tg/F+CCXIgLcxEuysW4OJfgklyKS3MZLsvluDxX4IpciStzFa7K1bg61+CaXItr
cx2uy/W4Prfj9tyBO3In7sxduCt34+7cg3tyL+7Nfbjvf3nfj/vzAB7Ig3gwD+GhPIyH8wgeyaN4
NI/hsTyOx/MEnsiTeDJP4ak8jafzDJ7Js3g2z+G5PI/n8wJeyH/yIl7MS3gpL+PlvIJX8ipezWt4
La/j9byBN/Im3sxbeCtv4+28g3fyLt7Ne3gv7+P9fIAP8iE+zEf4KB/j43yCT/IpPs1n+Cyf4/N8
gS/yJb7MV/gqX+PrfINv8i2+zXf4Lt/j+/yAH/IjfsxP+Ck/4+f8gl/yK37Nb/gtv+P3/IE/8if+
zF/4K3/j7/yDf/IvFlYBMRIiVpyghJLQEkbCSjgJLxEkokSSyOIlikSVaBJdYkhMiSWxJY7ElXgS
XxJIQkkkJCyJJYkklWSSXFJISkklqSWNpJV0kl4ySEbJJL9JZskiWSWbZJccklNySW7JI3kln+SX
AlJQCklhKSJFpZgUlxJSUkpJaSkjZaWclJcKUlEqSWWpIlWlmlSXGlJTakltqSN1pZ7UlwbSUBpJ
Y2kiTeV3aSbNpYW0lFbSWtrIH9JW2kl76SAdpZN0li7SVbpJd+khPaWX9JY+0lf6SX8ZIANlkAyW
ITJUhslwGSEjZZSMljEyVsbJeJkgE2WSTJYpMlWmyXSZITNllsyWOTJX5sl8WSAL5U9ZJItliSyV
ZbJcVshKWSWrZY2slXWyXjbIRtkkm2WLbJVtsl12yE7ZJbtlj+yVfbJfDshBOSSH5YgclWNyXE7I
STklp+WMnJVzcl4uyEW5JJflilyVa3JdbshNuSW35Y7clXtyXx7IQ3kkj+WJPJVn8lxeyEt5Ja/l
jbyVd/JePshH+SSf5Yt8lW/yXX7IT/klAqCgRkM0WAQUNZSG1jAaVsNpeI2gETWSRlavUTSqRtPo
GkNjaiyNrXE0rsbT+JpAE2oiJS2ohbSwFtGiWkyLawktqaW0tJbRslpOy2sFraiVtLJW0apaTatr
Da2ptTS35tG8mk/za4G/K19b62hdraf1tYE21EbaWJtoU/1dm2lzbaEttZW21jb6h7bVdtpeO2hH
7aSdtYt21W7aXXtoT+2lvbWP9tV+2l8H6EAdpIN1iA7VYTpcR+hIHaWjdYyO1XE6XifoRJ2kk3WK
TtVpOl1n6EydpbN1js7VeTpfF+hC/VMX6WJdokt1mS7XFbpSV+lqXaNrdZ2u1w26UTfpZt2iW3Wb
btcdulN36W7do3t1n+7XA3pQD+lhPaJH9Zge1xN6Uk/paT2jZ/WcntcLelEv6WW9olf1ml7XG3pT
b+ltvaN39Z7e1wf6UB/pY32iT/WZPtcX+lJf6Wt9o2/1nb7XD/pRP+ln/aJf9Zt+1x/6U3+pqP4D
/l5umQ==
"""
))))

class Config(object):
	def __getattr__(self, key):
		return None

class RedirectResponse(object):
	def __init__(self, path):
		self.path = path

class RedirectHandler(HTTPRedirectHandler):
	def http_error_302(self, req, fp, code, msg, headers):
		return RedirectResponse(headers['Location'])
	http_error_301 = http_error_302

class EasyMixin(object):

	def __getitem__(self, key):
		if isinstance(key, int):
			if key < 0:
				key += self._easysize()
			return self._easyget(key, key+1)
		elif isinstance(key, slice):
			if key.step is not None:
				raise TypeError('slice step must be None')
			start = key.start
			if start is None:
				start = 0
			stop = key.stop
			if stop is None:
				stop = self._easysize()
			if start < 0:
				start += self._easysize()
			if stop < 0:
				stop += self._easysize()
			return self._easyget(start, stop)
		else:
			off, sz = key
			if off < 0:
				off += self._easysize()
			data = self._easyget(off, off + sz)
			fmt = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
			return struct.unpack('>' + fmt[sz], data)[0]
	
	def offset(self, offset, size=None):
		if size is None:
			size = self._easysize() - offset
		return OffsetFilter(self, offset, size)

	def pieces(self, size, count=None):
		if count is None:
			count = self._easysize() // size
		for offset in range(0, size * count, size):
			yield self.offset(offset,size)
	
class HandleWrapper(EasyMixin):

	def __init__(self, handle):
		self.__handle = handle
		self.__size = None
		self.__virtualpos = None
		self.__actualpos = None

	def __seek(self, pos):
		if pos < 0:
			pos = self.__size + pos
		self.__virtualpos = pos
	
	def __read(self, sz):
		if self.__virtualpos != self.__actualpos:
			self.__handle.seek(self.__virtualpos)
			self.__actualpos = self.__virtualpos
		data = self.__handle.read(sz)
		self.__actualpos += sz
		return data

	def _easyget(self, start, stop):
		self.__seek(start)
		return self.__read(stop - start)

	def _easysize(self):
		if self.__size is None:
			self.__handle.seek(0, os.SEEK_END)
			self.__size = self.__handle.tell()
			self.__actualpos = None
		return self.__size

class BytesWrapper(EasyMixin):

	def __init__(self, bytes):
		self.__bytes = bytes
	
	def _easyget(self, start, stop):
		return self.__bytes[start:stop]

	def _easysize(self):
		return len(self.__bytes)

class OffsetFilter(EasyMixin):

	def __init__(self, em, offset, size):
		self.__em = em
		self.__offset = offset
		self.__size = size
	
	def offset(self, offset, size=None):
		if size is None:
			size = self.__size - offset
		return OffsetFilter(self.__em, self.__offset + offset, size)
	
	def _easyget(self, start, stop):
		offset = self.__offset
		return self.__em[start+offset:stop+offset]
	
	def _easysize(self):
		return self.__size

'''
class CacheFilter(EasyMixin):

	class Item(object):
		__slots__ = ['data', 'time']

	def __init__(self, em, cache_size=32):
		self.__em = em
		self.__cache = {}
		self.__cachesize = cache_size
		self.__cachetime = 0

	def __clean(self):
		while len(self.__cache) > self.__cachesize:
			cachetime, pos = min((item.time, pos) for pos, item in self.__cache.items())
			del self.__cache[pos]
	
	def _easyget(self, start, stop):

		sz = stop - start
		item = self.__cache.get(start)
		if item is not None and len(item.data) < sz:
			item = None

		if item is None:
			item = self.__cache[start] = CacheFilter.Item()
			item.data = self.__em[start:stop]

		item.time = self.__cachetime
		self.__cachetime += 1
		self.__clean()
		
		return item.data[:sz]
'''
	
class DMGFilter(EasyMixin):

	__decompressors = {
		0x00000001: lambda x, s: x,
		0x00000002: lambda x, s: '\0'.encode('ascii') * s,
		0x80000005: lambda x, s: zlib.decompress(x),
	}

	class Chunk(object):

		__slots__ = ['type', 'comment', 'uoffset', 'usize', 'coffset', 'csize']

		def __init__(self, type, comment, uoffset, usize, coffset, csize):
			self.type = type
			self.comment = comment
			self.uoffset = uoffset
			self.usize = usize
			self.coffset = coffset
			self.csize = csize

		def __repr__(self):
			return 'Chunk(type=%08x, comment=%d, uoffset=%d, usize=%d, coffset=%d, csize=%d)' % (
				self.type,
				self.comment,
				self.uoffset,
				self.usize,
				self.coffset,
				self.csize
			)

		def __compare(self, other, op):
			if isinstance(other, int):
				return op(self.uoffset, other)
			else:
				return op(self.uoffset, other.uoffset)

		def __lt__(self, other):
			return self.__compare(other, operator.lt)
		def __gt__(self, other):
			return self.__compare(other, operator.gt)

	def __init__(self, em):

		logging.debug('initializing DMG driver')
		self.__em = em

		xml_offset = em[-512+216,8]
		xml_size = em[-512+224,8]
		logging.debug('DMG XML of size %d at offset %d', xml_size, xml_offset)

		xml = em[xml_offset:xml_offset+xml_size]
		info = self.parse_plist(xml)
		blocks = info['resource-fork']['blkx']

		block = next(blk for blk in blocks if 'Apple_HFS' in blk['Name'])
		bdata = block['Data']
		blkx = BytesWrapper(bdata)
		
		if not (
			blkx[0,4] == 0x6D697368 and
			blkx[4,4] == 1 and
			blkx[24,8] == 0
		):
			raise ValueError('unsupported mish block')
		
		nchunks = blkx[200,4]
		logging.debug('DMG has %d chunks', nchunks)
		if len(bdata) - 204 != nchunks * 40:
			raise ValueError('bad mish size')
	
		chunks = self.__chunks = []
		for piece in blkx.offset(204).pieces(40):
			chunk_type = piece[0,4]
			chunk_comment = piece[4,4]
			chunk_uncompressed_start = piece[8,8] * 512
			chunk_uncompressed_size = piece[16,8] * 512
			chunk_compressed_start = piece[24,8]
			chunk_compressed_size = piece[32,8]
			if chunk_uncompressed_size:
				chunks.append(DMGFilter.Chunk(
					type = chunk_type,
					comment = chunk_comment,
					uoffset = chunk_uncompressed_start,
					usize = chunk_uncompressed_size,
					coffset = chunk_compressed_start,
					csize = chunk_compressed_size
				))

		chunks.sort(key=lambda chunk: chunk.uoffset)
		size = self.__size = blkx[16,8] * 512
		logging.debug('DMG size is %d bytes', size)
	
	@property
	def size(self):
		return self.__size

	def _easyget(self, start, stop):

		first_byte = start
		last_byte = stop - 1
		first_chunk_index = bisect.bisect(self.__chunks, first_byte) - 1
		last_chunk_index = bisect.bisect(self.__chunks, last_byte) - 1

		uncompressed_data = []
		for chunk_index in range(first_chunk_index, last_chunk_index + 1):
			chunk = self.__chunks[chunk_index]
			uncompressed_data.append(self.decompress_chunk(self.__chunks[chunk_index]))
		uncompressed_data = bytes().join(uncompressed_data)

		first_chunk = self.__chunks[first_chunk_index]
		first_byte -= first_chunk.uoffset
		last_byte -= first_chunk.uoffset
		return uncompressed_data[first_byte:last_byte+1]

	def _easysize(self):
		return self.__size

	def decompress_chunk(self, chunk):
		compressed_data = self.__em[chunk.coffset:chunk.coffset+chunk.csize]
		return self.__decompressors[chunk.type](compressed_data, chunk.usize)
	
	def parse_plist(self, xml):
		tree = ElementTree.fromstring(xml)
		if not (tree.tag == 'plist' and len(tree) == 1):
			raise ValueError('bad DMG plist')
		return self.parse_plist_obj(tree[0])

	def parse_plist_obj(self, node):
		return getattr(self, 'parse_plist_obj_%s' % node.tag)(node)
	
	def parse_plist_obj_dict(self, node):
		ret = {}
		if len(node) % 2 != 0:
			raise ValueError('bad DMG plist')
		for keynode, valuenode in zip(node[0::2], node[1::2]):
			ret[keynode.text] = self.parse_plist_obj(valuenode)
		return ret
	
	def parse_plist_obj_array(self, node):
		return [self.parse_plist_obj(subnode) for subnode in node]

	def parse_plist_obj_string(self, node):
		return node.text

	def parse_plist_obj_data(self, node):
		return binascii.a2b_base64(node.text)

class HFSDriver(object):

	class Util(object):

		@staticmethod
		def swap32(n):
			n &= (1 << 32) - 1
			n = (
				(n >> 24 & 0x000000FF) |
				(n >> 8  & 0x0000FF00) |
				(n << 8  & 0x00FF0000) |
				(n << 24 & 0xFF000000)
			)
			n &= (1 << 32) - 1
			return n

		@staticmethod
		def swap64(n):
			n &= (1 << 64) - 1
			n = (
				(n >> 56 & 0x00000000000000FF) |
				(n >> 40 & 0x000000000000FF00) |
				(n >> 24 & 0x0000000000FF0000) |
				(n >> 8  & 0x00000000FF000000) |
				(n << 8  & 0x000000FF00000000) |
				(n << 24 & 0x0000FF0000000000) |
				(n << 40 & 0x00FF000000000000) |
				(n << 56 & 0xFF00000000000000)
			)
			n &= (1 << 64) - 1
			return n

	class Fork(EasyMixin):

		def __init__(self, hfs, forkdata):
			self.__hfs = hfs
			self.__logical_size = forkdata[0,8]
			self.__total_blocks = forkdata[12,4]
			self.__blocks = []
			for extent in forkdata.offset(16).pieces(8, 8):
				start_block = extent[0,4]
				block_count = extent[4,4]
				self.__blocks.extend(range(start_block, start_block + block_count))

		def __retrieve_block(self, blknum):
			while blknum >= len(self.__blocks):
				raise 123
			return self.__blocks[blknum]
	
		def  _easyget(self, start, stop):
			hfsblksz = self.__hfs.block_size
			data = []
			while start < stop:
				blknum = self.__retrieve_block(start // hfsblksz)
				blkoff = start % hfsblksz
				blksz = min(hfsblksz - blkoff, stop - start)
				emoff = blknum * hfsblksz + blkoff
				data.append(self.__hfs.em[emoff:emoff+blksz])
				start += blksz
			return bytes().join(data)

		def _easysize(self):
			return self.__logical_size
	
	class ResourceFork(Fork):

		def __init__(self, hfs, forkdata):
			hfs.Fork.__init__(self, hfs, forkdata)
			headem = BytesWrapper(self[0:16])
			resources = self.__resources = []
			data_offset = headem[0,4]
			map_offset = headem[4,4]
			map_size = headem[12,4]
			mapem = BytesWrapper(self[map_offset:map_offset+map_size])
			types_list_offset = mapem[24,2]
			types_count = (mapem[types_list_offset,2] + 1) & 0xFFFF
			for sem in mapem.offset(types_list_offset + 2).pieces(8, types_count):
				resource_type = sem[0:4]
				resource_count = (sem[4,2] + 1) & 0xFFFF
				resource_list_offset = sem[6,2]
				for resource in mapem.offset(types_list_offset + resource_list_offset).pieces(12, resource_count):
					resource_id = resource[0,2]
					resource_data_offset = resource[4,4]
					resource_data_size = self[data_offset+resource_data_offset,4]
					resources.append((resource_type, resource_id, self.offset(
						data_offset+resource_data_offset+4, resource_data_size)))

		def get_resources(self, type=None, id=None):
			ret = []
			if not isinstance(type, bytes):
				type = type.encode('ascii')
			for resource in self.__resources:
				if type is not None and resource[0] != type:
					continue
				if id is not None and resource[1] != id:
					continue
				ret.append(resource[2])
			return ret
	
	class FileFolder(object):

		def __init__(self, record, parent, rectype):
	
			self.__record = record
			self.__parent = parent
			self.__name = record.key.node_name

			em = BytesWrapper(record.data)
			if em[0,2] != rectype:
				raise ValueError('bad record on file')
			self.__cnid = em[8,4]

			self.__admin_flags = em[40,1]
			self.__owner_flags = em[41,1]

		record = property(lambda s: s.__record)
		parent = property(lambda s: s.__parent)
		name = property(lambda s: s.__name)
		cnid = property(lambda s: s.__cnid)
		admin_flags = property(lambda s: s.__admin_flags)
		owner_flags = property(lambda s: s.__owner_flags)

		def __repr__(self):
			return '<%s name=%r>' % (self.__class__.__name__, self.name)

		@property
		def full_path(self):
			if self.parent:
				return self.parent.full_path + [self.name]
			else:
				return []
	
	class File(FileFolder):

		def __init__(self, record, parent):
			HFSDriver.FileFolder.__init__(self, record, parent, 0x0002)

		@property
		def data(self):
			hfs = self.record.node.btree.hfs
			if self.owner_flags & 0x20: # compressed
				attrkey = hfs.attributes.Key(cnid=self.cnid, key_name="com.apple.decmpfs")
				attrrec = hfs.attributes.find_record_for_key(attrkey)
				attrem = BytesWrapper(attrrec.data)
				attrtype = attrem[0,4]
				if attrtype == 0x10:
					attrsize = attrem[12,4]
					compmagic = HFSDriver.Util.swap32(attrem[16,4])
					comptype = HFSDriver.Util.swap32(attrem[20,4])
					uncompsize = HFSDriver.Util.swap64(attrem[24,8])
					if comptype == 0x03:
						if attrem[32,1] == 0xFF:
							return attrem[33:33+uncompsize]
						else:
							return zlib.decompress(attrem[32:16+attrsize])
					elif comptype == 0x04:
						rsrcfork = hfs.ResourceFork(hfs, BytesWrapper(self.record.data[168:248]))
						cmpfrsrc = rsrcfork.get_resources(type='cmpf', id=1)[0]
						numchunks = HFSDriver.Util.swap32(cmpfrsrc[0,4])
						chunks = []
						for cem in cmpfrsrc.offset(4).pieces(8, numchunks):
							offset = HFSDriver.Util.swap32(cem[0,4])
							length = HFSDriver.Util.swap32(cem[4,4])
							if cmpfrsrc[offset,1] == 0xFF:
								chunks.append(cmpfrsrc[offset+1:offset+length])
							else:
								chunks.append(zlib.decompress(cmpfrsrc[offset:offset+length]))
						return bytes().join(chunks)
					else:
						raise NotImplementedError
				else:
					raise NotImplementedError
			else:
				datafork = hfs.Fork(hfs, BytesWrapper(self.record.data[88:168]))
				return datafork[:]

	class Folder(FileFolder):

		def __init__(self, record, parent):
			HFSDriver.FileFolder.__init__(self, record, parent, 0x0001)

		@property
		def contents(self):

			btree = self.record.node.btree
			trec = btree.find_record_for_key(btree.Key(parent_cnid=self.cnid))

			records = []
			rec = trec.next_record
			while rec.key.parent_cnid == self.cnid:
				records.append(rec)
				rec = rec.next_record

			contents = {}
			for rec in records:
				ff = {
					0x0001: btree.hfs.Folder,
					0x0002: btree.hfs.File,
				}[BytesWrapper(rec.data)[0,2]](rec, self)
				contents[ff.name] = ff
			
			return contents

	class BTree(object):

		class Key(object):
			def __init__(self, data):
				self.data = data

		class Record(object):

			def __init__(self, node, recnum, start, stop):
				em = BytesWrapper(node.em[start:stop])
				keylen = em[0,2]
				self.key = node.btree.Key(em[2:2+keylen])
				self.data = em[2+keylen:]
				self.node = node
				self.recnum = recnum

			@property
			def prev_record(self):
				num = self.recnum - 1
				if num >= 0:
					return self.node.records[num]
				if self.node.prev_node:
					return self.node.prev_node.records[-1]
				return None

			@property
			def next_record(self):
				num = self.recnum + 1
				if num < len(self.node.records):
					return self.node.records[num]
				if self.node.next_node:
					return self.node.next_node.records[0]
				return None

		class DataRecord(Record):
			pass

		class PointerRecord(Record):
			def __init__(self, node, recnum, start, stop):
				node.btree.Record.__init__(self, node, recnum, start, stop)
				self.__target_node = BytesWrapper(self.data)[0,4]
			target_node = property(lambda s: s.node.btree.Node(s.node.btree, s.__target_node))
		
		class Node(object):

			TypeLeaf = 255
			TypeIndex = 0
			TypeHeader = 1
			TypeMap = 2

			def __init__(self, btree, nodenum):

				nodesz = btree.node_size
				nodeoff = nodenum * nodesz

				self.__btree = btree
				self.__em = em = BytesWrapper(btree.em[nodeoff:nodeoff+nodesz])

				self.__flink = em[0,4]
				self.__blink = em[4,4]
				self.__kind = em[8,1]

				numrecords = em[10,2]
				recoffsets = []
				for recnum in range(numrecords):
					recoffoff = (recnum + 1) * -2
					recoffsets.append(em[recoffoff,2])

				recordtype = {
					self.TypeIndex: btree.PointerRecord,
					self.TypeLeaf: btree.DataRecord,
				}[self.__kind]

				records = self.__records = []
				recstarts = recoffsets
				recstops = recoffsets[1:] + [nodesz + numrecords * -2]
				for recnum, recstart, recstop in zip(range(numrecords), recstarts, recstops):
					records.append(recordtype(self, recnum, recstart, recstop))

			em = property(lambda s: s.__em)
			kind = property(lambda s: s.__kind)
			btree = property(lambda s: s.__btree)
			records = property(lambda s: s.__records)

			@property
			def prev_node(self):
				if self.__blink:
					return self.btree.Node(self.btree, self.__blink)
				else:
					return None

			@property
			def next_node(self):
				if self.__flink:
					return self.btree.Node(self.btree, self.__flink)
				else:
					return None

		def __init__(self, hfs, em):
			self.__hfs = hfs
			self.__em = em
			headem = BytesWrapper(em[14:128])
			self.__root_node = headem[2,4]
			self.__node_size = headem[18,2]

		hfs = property(lambda s: s.__hfs)
		em = property(lambda s: s.__em)
		root_node = property(lambda s: s.Node(s, s.__root_node))
		node_size = property(lambda s: s.__node_size)

		def find_record_for_key(self, key):

			node = self.root_node

			# get leaf node
			while True:

				lrecord = None
				for record in node.records:
					if key >= record.key:
						lrecord = record
					else:
						break

				node = lrecord.target_node
				if node.kind == node.TypeLeaf:
					break

			# get data record
			for record in node.records:
				if key == record.key:
					return record

			# record not found
			return None

	class Extents(BTree):
		pass
	
	class Catalog(BTree):

		class Key(object):
			def __init__(self, data=None, parent_cnid=None):
				if data is not None:
					em = BytesWrapper(data)
					self.parent_cnid = em[0,4]
					namelen = em[4,2]
					namebytes = data[6:6+2*namelen]
					self.node_name = namebytes.decode('utf-16-be')
					self.folded_node_name = self.fold(self.node_name)
				elif parent_cnid is not None:
					self.parent_cnid = parent_cnid
					self.node_name = bytes().decode('utf-16-be')
					self.folded_node_name = []
				else:
					raise TypeError
			def __repr__(self):
				return '<%s parent_cnid=%r node_name=%r>' % (self.__class__.__name__, self.parent_cnid, self.node_name)
			def __ge__(self, other):
				if self.parent_cnid > other.parent_cnid:
					return True
				if self.parent_cnid < other.parent_cnid:
					return False
				return self.folded_node_name >= other.folded_node_name
			def __eq__(self, other):
				return (self.parent_cnid == other.parent_cnid and
					self.folded_node_name == other.folded_node_name)
			def fold(self, name):
				folded = []
				for char in (ord(x) for x in name):
					temp = lower_case_table[char >> 8]
					if temp:
						char = lower_case_table[temp + (char & 0xFF)]
					if char:
						folded.append(char)
				return folded
	
	class Attributes(BTree):

		class Key(object):
			def __init__(self, data=None, cnid=None, key_name=None):
				if data is not None:
					em = BytesWrapper(data)
					self.cnid = em[2,4]
					namelen = em[10,2]
					namebytes = em[12:12+2*namelen]
					self.key_name = namebytes.decode('utf-16-be')
				elif cnid is not None and key_name is not None:
					self.cnid = cnid
					self.key_name = key_name
				else:
					raise TypeError
			def __ge__(self, other):
				if self.cnid > other.cnid:
					return True
				if self.cnid < other.cnid:
					return False
				return self.key_name >= other.key_name
			def __eq__(self, other):
				return (self.cnid == other.cnid and self.key_name == other.key_name)

	def __init__(self, em):

		self.__em = em
		headem = BytesWrapper(em[0x400:0x600])

		if not (
			headem[0,2] == 0x482B and
			headem[2,2] == 0x0004
		):
			raise ValueError('unsupported/bad HFS+ volume')

		self.__block_size = block_size = headem[40,4]

		(
			self.__allocation_fork,
			self.__extents_fork,
			self.__catalog_fork,
			self.__attributes_fork,
			self.__startup_fork
		) = (self.Fork(self, forkdata) for forkdata in headem.offset(112).pieces(80, 5))

		self.__extents = self.Extents(self, self.__extents_fork)
		self.__catalog = self.Catalog(self, self.__catalog_fork)
		self.__attributes = self.Attributes(self, self.__attributes_fork)
		
	em = property(lambda s: s.__em)
	block_size = property(lambda s: s.__block_size)

	extents = property(lambda s:s.__extents)
	catalog = property(lambda s:s.__catalog)
	attributes = property(lambda s:s.__attributes)

	@property
	def root_folder(self):
		key = self.__catalog.root_node.records[0].key
		record = self.__catalog.find_record_for_key(key)
		return self.Folder(record, None)

	def get(self, path):
		ff = self.root_folder
		for component in path:
			ff = ff.contents[component]
		return ff

def appleauth():

	print('Please enter your Apple ID and password.')
	print('If you do not have a developer account, sign up for free at https://developer.apple.com/ .')

	while True:

		response = config.opener.open(DMG_URL)
		if not isinstance(response, RedirectResponse) or 'daw.apple.com' not in response.path:
			break

		username = input('Apple ID: ')
		password = getpass('Password: ')
		response = config.opener.open(response.path)
		lhtml = response.read().decode('iso-8859-1')
		response.close()
		itag = re.search(r'<input [^<>]*name="wosid"[^<>]*>', lhtml).group(0)
		wosid = re.search(r'value="([^"]*)"', itag).group(1)
		ftag = re.search(r'<form [^<>]*name="appleConnectForm"[^<>]*>', lhtml).group(0)
		action = re.search(r'action="([^"]*)"', ftag).group(1)
		response = config.opener.open('https://daw.apple.com%s' % action, urlencode({
			'theAccountName': username,
			'theAccountPW': password,
			'theAuxValue': '',
			'wosid': wosid,
		}).encode('iso-8859-1'))
		data = response.read().decode('iso-8859-1')

		if ('URL=%s' % DMG_URL) in data:
			break
		else:
			print('Bad Apple ID or password. Is this account a registered developer account?')

config = Config()
config.xcodedmg = os.path.expanduser('~/Downloads/xcode4630916281a.dmg')

def run():

	if config.xcodedmg:
		em = HandleWrapper(open(config.xcodedmg, 'rb', 0))
	else:
		appleauth()
		raise 1

	koly = em[-512:]
	if hashlib.sha1(koly).hexdigest() != DMG_KOLY_SHA1:
		raise Exception('bad DMG')

	dmg = DMGFilter(em)
	hfs = HFSDriver(dmg)
	
	sdk = hfs.get(['Xcode.app','Contents','Developer','Platforms','iPhoneOS.platform',
		'Developer','SDKs','iPhoneOS6.1.sdk'])

	def walk(obj):
		if isinstance(obj, HFSDriver.Folder):
			for n, c in sorted(obj.contents.items()):
				walk(c)
		elif isinstance(obj, HFSDriver.File):
			obj.data

	walk(sdk)

def makedir(x):
	try:
		logging.debug('creating dir at %r', x)
		os.makedirs(x)
	except OSError:
		if not os.path.isdir(x):
			raise

def main(args):

	if len(args) != 1:
		print('Usage: %s <output directory>' % sys.argv[0])
		return 1

	config.prefix = args[0]	
	makedir(config.prefix)
	run()
	return 0

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
