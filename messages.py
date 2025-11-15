#! /usr/bin/env python3
'''
Implementation(s) of p2pIM message format(s).

Copyright 2025 Ilja Honkonen

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject
to the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from itertools import product

''' Version 0 message format for experimentation

JSON array consisting of 5 strings:
[version,timestamp,nonce,checksum,payload] where
version = 0
timestamp = yyyymmddhhmmss in UTC
nonce = nonce_bytes byte string
checksum = first checksum_bytes bytes of
           hex-formatted sha256 of payload
payload = from 0 to max_message_bytes - overhead_bytes byte string

Proof of work: int = |T - H| * S * A, where
T = PoW target
H = first pow_bytes of hex-formatted
         sha256 of timestamp+nonce+checksum
S = max(message_bytes, min_message_bytes) / min_message_bytes
A = max(utc_now - timestamp, min_message_age) / min_message_age
'''
class Message_v0:
	hash_func = sha256
	format_bytes = 16 # ["","","","",""]
	version_bytes = 1 # 0
	timestamp_bytes = 14 # yyyymmddhhmmss
	nonce_bytes = 10
	checksum_bytes = 12 # hex
	pow_bytes = 8 # hex
	pow_target = 2**(8*pow_bytes//2) - 1 # hex / 2
	# message size with 0 byte payload
	overhead_bytes = format_bytes + timestamp_bytes \
		+ nonce_bytes + version_bytes + checksum_bytes
	# smaller messages count as this large
	min_message_bytes = 8 + overhead_bytes
	max_payload_bytes = 128
	max_message_bytes = max_payload_bytes + overhead_bytes
	min_message_age = timedelta(seconds = 10)

	@staticmethod
	def get_checksum(payload: str):
		hasher = Message_v0.hash_func()
		hasher.update(payload.encode('utf-8'))
		return hasher.hexdigest()[0:Message_v0.checksum_bytes]

	@staticmethod
	def get_initial_pow(timestamp: str, nonce: str, checksum : str, target: int):
		hasher = Message_v0.hash_func()
		hasher.update(timestamp.encode('utf-8'))
		hasher.update(nonce.encode('utf-8'))
		hasher.update(checksum.encode('utf-8'))
		return abs(target - int(hasher.hexdigest()[0:Message_v0.pow_bytes], 16))

	def __init__(self):
		self.version = '0'
		self.timestamp_str = None
		self.timestamp_obj = None
		self.nonce = None
		self.checksum = None
		self.payload = None
		self.initial_pow = None
		self.current_pow = None
		self.utc_now = None

	def __str__(self):
		return '["{}","{}","{}","{}","{}"]'.format(self.version,
			self.timestamp_str, self.nonce, self.checksum, self.payload)
	def __repr__(self): return self.__str__()

	# decreases message's proof of work significantly
	def set_timestamp(self, utc_now: datetime = None):
		if utc_now == None:
			self.timestamp_obj = datetime.now(timezone.utc)
		else:
			self.timestamp_obj = utc_now.replace(tzinfo = timezone.utc)
		self.timestamp_str = self.timestamp_obj.strftime('%Y%m%d%H%M%S')

	# decreases message's proof of work significantly
	def set_payload(self, new_payload: str):
		if len(new_payload) > self.max_payload_bytes:
			raise RuntimeError('Payload too large')
		self.payload = new_payload
		self.checksum = self.get_checksum(self.payload)
		if self.nonce == None:
			self.nonce = 'a' * self.nonce_bytes
		self.initial_pow = self.get_initial_pow(
			self.timestamp_str, self.nonce, self.checksum, self.pow_target)

	# returns number of tries to get required_pow or better
	def update_nonce(self, required_pow = -1, utc_now = None):
		if required_pow < 0:
			required_pow = 2**(4*self.pow_bytes) - 1
		self.initial_pow = None
		self.current_pow = None
		tries = 0
		for i in product('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', repeat = self.nonce_bytes):
			tries += 1
			candidate = ''
			for c in i:
				candidate += c
			initial_pow = Message_v0.get_initial_pow(
				self.timestamp_str, candidate, self.checksum, self.pow_target)
			if initial_pow < required_pow:
				self.nonce = candidate
				self.initial_pow = initial_pow
				break
		if self.initial_pow == None:
			raise RuntimeError("Couldn't reach target proof of work")
		if utc_now == None:
			utc_now = datetime.now(timezone.utc)
		utc_now = utc_now.replace(tzinfo = timezone.utc)
		self.update_pow(utc_now)
		return tries


	def update_pow(self, utc_now):
		age = max(utc_now - self.timestamp_obj, self.min_message_age) / self.min_message_age
		size = max(len(self.__str__()), self.min_message_bytes) / self.min_message_bytes
		self.current_pow = min(2**(4*self.pow_bytes) - 1,
			int(self.initial_pow * age * size))


	''' Verifies and initializes from given string

	Initializes only if verification succeeds.
	Returns error as string or '' on success.
	'''
	def parse(self, s, required_pow, utc_now = None):
		if len(s) < self.overhead_bytes:
			return 'Message too short: ' + str(len(s)) + '<'+str(self.overhead_bytes) + '\n'

		if not s.startswith('["0","'):
			return 'Wrong format/version\n'
		if not s.endswith('"]'):
			return 'Wrong format/payload\n'

		# valid datetime
		d_start = 5+self.version_bytes
		d_end = d_start + self.timestamp_bytes
		timestamp_str = s[d_start:d_end]
		try:
			_ = int(timestamp_str)
		except:
			return 'Wrong format/datetime\n'

		if utc_now == None:
			utc_now = datetime.now(timezone.utc)
		if timestamp_str > utc_now.strftime('%Y%m%d%H%M%S'):
			return 'Datetime in future\n'

		n_start = 3 + d_end
		n_end = n_start + self.nonce_bytes
		nonce = s[n_start : n_end]
		c_start = 3 + n_end
		c_end = c_start + self.checksum_bytes
		checksum = s[c_start:c_end]

		initial_pow = Message_v0.get_initial_pow(
			timestamp_str, nonce, checksum, self.pow_target)
		if initial_pow > required_pow:
			return 'Required PoW: 0x' + required_pow.to_bytes(
				length = self.pow_bytes//2).hex() + '\n'

		try:
			timestamp_obj = datetime.strptime(
				timestamp_str, '%Y%m%d%H%M%S').replace(tzinfo = timezone.utc)
		except:
			return 'Wrong format/datetime\n'

		p_start = 3 + c_end
		payload = s[p_start:-2]
		checksum_reference = self.get_checksum(payload)
		if checksum != checksum_reference:
			return 'Wrong checksum\n'

		age = max(utc_now - timestamp_obj, self.min_message_age) / self.min_message_age
		size = max(len(s), self.min_message_bytes) / self.min_message_bytes
		current_pow = min(2**(4*self.pow_bytes) - 1,
			int(initial_pow * age * size))
		if current_pow > required_pow:
			return 'Required PoW: 0x' \
				+ required_pow.to_bytes(length = self.pow_bytes//2).hex() + '\n'

		self.timestamp_str = timestamp_str
		self.timestamp_obj = timestamp_obj
		self.nonce = nonce
		self.checksum = checksum
		self.payload = payload
		self.initial_pow = initial_pow
		self.current_pow = current_pow
		return ''


if __name__ == '__main__':
	timestamp = datetime(2000, 1, 2, 3, 4, 5)
	m = Message_v0()
	print('# message v0:      ', end = '')
	print('[version,timestamp   ,   nonce', end = '')
	print('    ,   checksum   , payload     ],   PoW')

	m.set_timestamp(timestamp)
	m.set_payload('')
	m.update_nonce(-1, timestamp)
	print('empty message:    ', m, '           0x'
		+ m.current_pow.to_bytes(length = m.pow_bytes//2).hex())

	m.set_payload('hello world')
	m.update_nonce(-1, timestamp)
	print('modified payload: ', m, '0x'
		+ m.current_pow.to_bytes(length = m.pow_bytes//2).hex())

	m.update_nonce(2**(4*m.pow_bytes - 10) - 1, timestamp)
	print('better PoW:       ', m, '0x'
		+ m.current_pow.to_bytes(length = m.pow_bytes//2).hex())

	m.set_timestamp(timestamp)
	m.update_nonce(2**(4*m.pow_bytes - 10) - 1,timestamp + 16*m.min_message_age)
	print('16x older message:', m, '0x'
		+ m.current_pow.to_bytes(length = m.pow_bytes//2).hex())
