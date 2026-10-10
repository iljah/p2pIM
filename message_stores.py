#! /usr/bin/env python3
'''
Message store that automatically removes messages with worst proof of work.

Copyright 2026 Ilja Honkonen

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

import asyncio
from datetime import datetime, timezone

# message id == initial proof of work
class Message_Store_v0:
	def __init__(self, worst_pow): # in hex
		self.messages = dict() # messages[initial_pow] = message
		self.lock = asyncio.Lock()
		self.worst_pow = worst_pow
		self.worst_current_pow = worst_pow # including decay, lower is better
		self.worst_pow_initially = worst_pow # initial pow of above message
		self.max_storage = 2**8
		self.utc_now = None # None == now() is used as needed

	async def get_nr_messages(self):
		async with self.lock:
			return len(self.messages)

	async def have_message(self, initial_pow: int):
		async with self.lock:
			return initial_pow in self.messages

	async def get_message(self, initial_pow: int):
		async with self.lock:
			if initial_pow in self.messages:
				return self.messages[initial_pow]
			else:
				return None

	async def get_utc_now(self):
		now = None
		async with self.lock:
			now = self.utc_now
		if now == None:
			return datetime.now(timezone.utc)
		else:
			return now

	async def set_utc_now(self, new_now: datetime | None):
		async with self.lock:
			self.utc_now = new_now
			# TODO update current_pow of messages?

	async def get_max_storage(self):
		async with self.lock:
			return self.max_storage

	async def set_max_storage(self, new_max: int):
		async with self.lock:
			self.max_storage = new_max
			# TODO remove messages that don't fit anymore

	# returns all messages' initial proof of work
	async def get_initial_pows(self):
		initial_pows = set()
		async with self.lock:
			for initial_pow in self.messages:
				initial_pows.add(initial_pow)
		return initial_pows

	# returns number of bytes needed for all messages
	async def get_storage_used(self):
		used = 0
		async with self.lock:
			for initial_pow in self.messages:
				used += len(self.messages[initial_pow])
		return used

	def get_worst_pow(self):
		return self.worst_current_pow, self.worst_pow_initially

	# update worst proof of work without updating messages' current pow
	async def set_worst_pow(self):
		async with self.lock:
			self.worst_current_pow = -1
			for initial_pow in self.messages:
				msg = self.messages[initial_pow]
				if self.worst_current_pow < msg.current_pow:
					self.worst_current_pow = msg.current_pow
					self.worst_pow_initially = msg.initial_pow
			if self.worst_current_pow < 0:
				self.worst_current_pow = self.worst_pow
				self.worst_pow_initially = self.worst_pow

	# updates all messages' proof of work and worst pow, call periodically
	async def update_worst_pow(self):
		utc_now = await self.get_utc_now()
		async with self.lock:
			for initial_pow in self.messages:
				self.messages[initial_pow].update_pow(utc_now)
		await self.set_worst_pow()

	async def pop(self, initial_pow):
		async with self.lock:
			_ = self.messages.pop(initial_pow, None)
		await self.set_worst_pow()

	# tries to add message to store, returns error as string or '' on success
	async def add(self, msg):
		msg_len = len(msg)
		if msg_len > await self.get_max_storage():
			return 'Message too large\n'
		async with self.lock:
			if msg.initial_pow in self.messages:
				return ''
		msg.update_pow(await self.get_utc_now())

		# potentially make room for new message
		while \
			await self.get_nr_messages() > 0 \
			and msg_len + await self.get_storage_used() > await self.get_max_storage() \
		:
			worst_current, worst_initially = self.get_worst_pow()
			if msg.current_pow > worst_current:
				return 'Required pow: 0x{}\n'.format(
					worst_current.to_bytes(length = msg.pow_bytes//2).hex())
			else:
				await self.pop(worst_initially)

		async with self.lock:
			self.messages[msg.initial_pow] = msg
		await self.set_worst_pow()
		return ''


async def main():
	from messages import Message_v0

	store = Message_Store_v0(Message_v0.worst_pow)
	await store.set_max_storage(Message_v0.min_message_bytes)

	timestamp = datetime(2000, 1, 2, 3, 4, 5, tzinfo = timezone.utc)
	await store.set_utc_now(timestamp)
	print('Initialized message store fitting',
		await store.get_max_storage(), 'bytes worth of message(s)')

	m1 = Message_v0()
	m1.set_timestamp(timestamp)
	m1.set_payload('1')
	m1.update_nonce(3459891604, timestamp) # smaller than next
	print('Adding {} byte message with payload "{}" and current proof of work {}' \
		.format(len(str(m1)), m1.payload, m1.current_pow))
	result = await store.add(m1)
	if result != '':
		exit('Unexpected failure')

	await store.update_worst_pow()

	m2 = Message_v0()
	m2.set_timestamp(timestamp)
	m2.set_payload('2')
	m2.update_nonce(-1, timestamp)
	print('Adding {} byte message with payload "{}" and current proof of work {}' \
		.format(len(str(m2)), m2.payload, m2.current_pow))
	result = await store.add(m2)
	if result == '':
		exit('Unexpected success')

	m3 = Message_v0()
	m3.set_timestamp(timestamp)
	m3.set_payload('3')
	m3.update_nonce(-1, timestamp)
	print('Adding {} byte message with payload "{}" and current proof of work {}' \
		.format(len(str(m3)), m3.payload, m3.current_pow))
	result = await store.add(m3)
	if result != '':
		exit('Unexpected failure')

	m4 = Message_v0()
	m4.set_timestamp(timestamp)
	m4.set_payload('444444444')
	m4.update_nonce(533543722, timestamp) # smaller than previous
	print('Adding {} byte message with payload "{}" and current proof of work {}' \
		.format(len(str(m4)), m4.payload, m4.current_pow))
	result = await store.add(m4)
	if result == '':
		exit('Unexpected success')

	print('Stored message(s): version, timestamp, nonce, checksum, payload')
	for message in store.messages:
		print(store.messages[message])

if __name__ == '__main__':
	asyncio.run(main())
