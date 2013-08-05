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

try:
	next
except NameError: # Python 2.5
	next = lambda x: x.next()

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
			return self._easyget(start, stop)
		else:
			off, sz = key
			data = self._easyget(off, off + sz)
			fmt = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
			return struct.unpack('>' + fmt[sz], data)[0]
	
	def offset(self, offset):
		return OffsetFilter(self, offset)
	
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

	def __init__(self, em, offset=0):
		self.__em = em
		self.__offset = offset
	
	def offset(self, offset):
		return OffsetFilter(self.__em, self.__offset + offset)
	
	def _easyget(self, start, stop):
		offset = self.__offset
		return self.__em[start+offset:stop+offset]
	
	def _easysize(self):
		return self.__em._easysize() - self.__offset

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
	
class DMGDriver(EasyMixin):

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
		for offset in range(204, len(bdata), 40):
			chunk_type = blkx[offset,4]
			chunk_comment = blkx[offset+4,4]
			chunk_uncompressed_start = blkx[offset+8,8] * 512
			chunk_uncompressed_size = blkx[offset+16,8] * 512
			chunk_compressed_start = blkx[offset+24,8]
			chunk_compressed_size = blkx[offset+32,8]
			if chunk_uncompressed_size:
				chunks.append(DMGDriver.Chunk(
					type = chunk_type,
					comment = chunk_comment,
					uoffset = chunk_uncompressed_start,
					usize = chunk_uncompressed_size,
					coffset = chunk_compressed_start,
					csize = chunk_compressed_size
				))

		chunks.sort(key=lambda chunk: chunk.uoffset)
		size = self.__size = chunks[-1].uoffset + chunks[-1].usize
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

	def __init__(self, em):

		self.__em = em
		headem = BytesWrapper(em[0x400:0x600])

		if not (
			headem[0,2] == 0x482B and
			headem[2,2] == 0x0004
		):
			raise ValueError('unsupported/bad HFS+ volume')

		block_size = headem[40,4]
		print(block_size)
		raise 1

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

	dmg = DMGDriver(em)
	hfs = HFSDriver(dmg)

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
