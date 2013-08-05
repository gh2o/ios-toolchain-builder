#!/usr/bin/env python

from __future__ import with_statement

DMG_URL = 'https://developer.apple.com/downloads/download.action'
DMG_PATH = "Developer_Tools/xcode_4.6.3/xcode4630916281a.dmg"
DMG_SIZE = 1723816316
DMG_KOLY_SHA1 = "f21001cc2b7eb230003250945156b1b6354ccd77"

import os
import sys
import time
import logging
import re
import hashlib
import struct
import binascii
from xml.etree import ElementTree
from getpass import getpass

logging.getLogger().setLevel(logging.DEBUG)

try: # Python 3
	from urllib.request import build_opener, HTTPRedirectHandler, HTTPCookieProcessor
	from urllib.parse import urlencode
	from io import BytesIO
except ImportError: # Python 2
	from urllib2 import build_opener, HTTPRedirectHandler, HTTPCookieProcessor
	from urllib import urlencode
	from cStringIO import StringIO as BytesIO
	input = raw_input
	range = xrange

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

class HandleWrapper(object):

	def __init__(self, handle, size):
		self.__handle = handle
		self.__size = size
	
	def __seek(self, off):
		if off < 0:
			self.__handle.seek(self.__size + off)
		else:
			self.__handle.seek(off)
	
	def __getitem__(self, key):
		if isinstance(key, int):
			self.__seek(key)
			return self.__handle.read(1)
		elif isinstance(key, slice):
			if key.step is not None:
				raise TypeError('slice step must be None')
			self.__seek(key.start)
			return self.__handle.read(key.stop - key.start)
		else:
			off, sz = key
			self.__seek(off)
			data = self.__handle.read(sz)
			fmt = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
			return struct.unpack('>' + fmt[sz], data)[0]

class DMGDriver(HandleWrapper):

	class Chunk(object):
		__slots__ = ['type', 'comment', 'uoffset', 'usize', 'coffset', 'csize']
		def __init__(self, type, comment, uoffset, usize, coffset, csize):
			self.type = type
			self.comment = comment
			self.uoffset = uoffset
			self.usize = usize
			self.coffset = coffset
			self.csize = csize

	def __init__(self, handle, size):

		logging.debug('initializing DMG driver')
		super(DMGDriver, self).__init__(handle, size)

		xml_offset = self[-512+216,8]
		xml_size = self[-512+224,8]
		logging.debug('DMG XML of size %d at offset %d', xml_size, xml_offset)

		xml = self[xml_offset:xml_offset+xml_size]
		info = self.parse_plist(xml)
		blocks = info['resource-fork']['blkx']

		block = next(blk for blk in blocks if 'Apple_HFS' in blk['Name'])
		bdata = block['Data']
		blkx = HandleWrapper(BytesIO(bdata),len(bdata))
		
		if not (
			blkx[0,4] == 0x6D697368 and
			blkx[4,4] == 1 and
			blkx[24,8] == 0
		):
			logging.error('unsupported mish block')
			raise ValueError('unsupported mish block')
		
		nchunks = blkx[200,4]
		logging.debug('DMG has %d chunks', nchunks)
		if len(bdata) - 204 != nchunks * 40:
			logging.error('bad mish size')
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

		self.__size = max(chunk.uoffset + chunk.usize for chunk in chunks)
	
	@property
	def size(self):
		return self.__size
	
	def parse_plist(self, xml):
		tree = ElementTree.fromstring(xml)
		if not (tree.tag == 'plist' and len(tree) == 1):
			logging.error('bad DMG plist')
			raise ValueError('bad DMG plist')
		return self.parse_plist_obj(tree[0])

	def parse_plist_obj(self, node):
		return getattr(self, 'parse_plist_obj_%s' % node.tag)(node)
	
	def parse_plist_obj_dict(self, node):
		ret = {}
		if len(node) % 2 != 0:
			logging.error('plist dict does not have even number of elements')
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
		handle = open(config.xcodedmg, 'rb')
	else:
		appleauth()
		raise 1

	handle.seek(DMG_SIZE - 512)
	koly = handle.read(512)
	if hashlib.sha1(koly).hexdigest() != DMG_KOLY_SHA1:
		logging.error('bad DMG identification block! wrong DMG file?')
		raise Exception('bad DMG')

	dmg = DMGDriver(handle, DMG_SIZE)
	dmg.size

def makedir(x):
	try:
		logging.debug('creating dir at %r', x)
		os.makedirs(x)
	except OSError:
		if not os.path.isdir(x):
			logging.error('failed to create dir at %r', x)
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
