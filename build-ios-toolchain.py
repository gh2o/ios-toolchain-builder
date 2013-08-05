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
except ImportError: # Python 2
	from urllib2 import build_opener, HTTPRedirectHandler, HTTPCookieProcessor
	from urllib import urlencode
	input = raw_input

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
		print(len(bdata))
	
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

class Step(object):

	def __init__(self):
		self.step_name = type(self).__name__
		self.info_path = os.path.join(config.infodir, self.step_name)

	def get_requirements(self):
		return []

	def get_tag(self):
		return ''

	def needs_rebuild(self):
		return False
	
	def read_info(self):
		try:
			with open(self.info_path) as f:
				timestamp = float(f.readline().strip())
				tag = f.read().strip()
				return (timestamp, tag)
		except:
			return (None, None)
	
	def write_info(self, timestamp, tag):
		with open(self.info_path, 'w') as f:
			f.write('%f\n' % timestamp)
			f.write('%s\n' % tag)
	
	def maybe_build(self):
		logging.debug('checking if %s needs to be rebuilt' % self.step_name)
		timestamp, tag = self.read_info()
		need_build = (
			self.needs_rebuild() or
			timestamp is None or
			tag != self.get_tag()
		)
		for req in self.get_requirements():
			req.maybe_build()
			req_timestamp, req_tag = req.read_info()
			need_build = need_build or timestamp < req_timestamp
		if need_build:
			logging.debug('rebuilding %s' % self.step_name)
			self.build()
			self.write_info(time.time(), self.get_tag())
		else:
			logging.debug('%s is up-to-date' % self.step_name)
	
	def build(self):
		pass

class Headers(Step):

	def get_tag(self):
		return DMG_KOLY_SHA1

	def build(self):

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

		raise 1

class Toolchain(Step):
	def get_tag(self):
		return '%f' % os.path.getmtime(__file__)
	def get_requirements(self):
		return [Headers()]

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

def makedir(x):
	try:
		logging.debug('creating dir at %r', x)
		os.makedirs(x)
	except OSError:
		if not os.path.isdir(x):
			logging.error('failed to create dir at %r', x)
			raise

config = Config()
config.xcodedmg = os.path.expanduser('~/Downloads/xcode4630916281a.dmg')

def main(args):

	default_prefix = os.path.expanduser('~/ios-toolchain')
	prefix = '' #input('Path to toolchain [%s]: ' % default_prefix)
	prefix = config.prefix = prefix or default_prefix

	config.infodir = os.path.join(prefix, 'info')
	config.builddir = os.path.join(prefix, 'build')

	config.opener = build_opener(RedirectHandler(), HTTPCookieProcessor())

	makedir(config.infodir)
	makedir(config.builddir)

	toolchain = Toolchain()
	toolchain.maybe_build()

if __name__ == "__main__":
	main(sys.argv[1:])
