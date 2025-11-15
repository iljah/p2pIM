#! /usr/bin/env python3
'''
Sends and receives p2pIM messages over TCP, keeps them in memory.

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

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import asyncio
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from messages import Message_v0

messages = dict() # messages[initial_pow] = message
required_pow = 2**(4*Message_v0.pow_bytes) - 1
max_storage = 128
utc_now = None # != None when testing


def get_storage_used():
	used = 0
	for i in messages:
		used += len(str(messages[i]))
	return used


# returns worst initial_pow, current_pow of stored messages
def get_worst_pow():
	worst_initial, worst_current = 0, 0
	if len(messages) > 0:
		for initial_pow in messages:
			message = messages[initial_pow]
			if utc_now != None:
				message.update_pow(utc_now)
			else:
				message.update_pow(datetime.now(timezone.utc))
			if worst_current < message.current_pow:
				worst_current = message.current_pow
				worst_initial = initial_pow
	return worst_initial, worst_current


# checks proof of work, etc
async def handle_message(reader, writer):
	global required_pow

	data = await reader.read()
	message = Message_v0()
	reply = message.parse(data.decode('utf-8'), required_pow, utc_now)
	if reply != '':
		writer.write(reply.encode('utf-8'))
		await writer.drain()
		writer.close()
		await writer.wait_closed()
		return

	# special payloads, not saved
	if message.payload == '__info__':
		reply = 'Required pow: 0x' \
			+ required_pow.to_bytes(length = Message_v0.pow_bytes//2).hex() + '\n'
		writer.write(reply.encode('utf-8'))
		await writer.drain()
		writer.close()
		await writer.wait_closed()
		return
	elif message.payload == '__messages__':
		reply = ''
		for pow_ in messages:
			reply += str(messages[pow_]) + '\n'
		writer.write(reply.encode('utf-8'))
		await writer.drain()
		writer.close()
		await writer.wait_closed()
		return
	elif message.payload == '__exit__':
		if utc_now != None:
			writer.write(b'Exiting...\n')
			await writer.drain()
			writer.close()
			await writer.wait_closed()
			exit(0)
		else:
			writer.write(b'Ignoring __exit__\n')
			await writer.drain()
			writer.close()
			await writer.wait_closed()
			return
	elif message.payload == '__memory__':
		if utc_now != None:
			mem = get_storage_used()
			reply = 'Total memory used by messages: {:d}\n'.format(mem)
			writer.write(reply.encode('utf-8'))
			await writer.drain()
			writer.close()
			await writer.wait_closed()
			return
		else:
			writer.write(b'Ignoring __memory__\n')
			await writer.drain()
			writer.close()
			await writer.wait_closed()
			return

	msg_str = str(message)
	# potentially make room for new message
	while len(messages) > 0 and len(msg_str) + get_storage_used() > max_storage:
		worst_initial, worst_current = get_worst_pow()
		if message.current_pow > worst_current:
			reply = 'Required pow: 0x' \
				+ worst_current.to_bytes(length = Message_v0.pow_bytes//2).hex() + '\n'
			writer.write(reply.encode('utf-8'))
			await writer.drain()
			writer.close()
			await writer.wait_closed()
			return
		else:
			_ = messages.pop(worst_initial, None)
	messages[message.initial_pow] = message
	required_pow = max(required_pow, message.current_pow)
	writer.write(b'ok\n')
	await writer.drain()
	writer.close()
	await writer.wait_closed()

def handle_exception(loop, context):
	return

async def server(args):
	l = asyncio.get_running_loop()
	l.set_exception_handler(handle_exception)
	s = await asyncio.start_server(
		handle_message, args.addr, args.port)
	async with s:
		try: await s.serve_forever()
		except: return


if __name__ == '__main__':
	parser = ArgumentParser(
		formatter_class = ArgumentDefaultsHelpFormatter
	)
	parser.add_argument('--mem', metavar = 'M', type = int, default = 128,
		help = 'Store at most M bytes of messages.')
	parser.add_argument('--addr', metavar = 'A', type = str, default = '127.0.0.1',
		help = 'Listen for connections on IP address A.')
	parser.add_argument('--port', metavar = 'P', type = int, default = 8765,
		help = 'Listen for connections on IP port P.')
	parser.add_argument('--current-time', metavar = 'N', type = str, default = None,
		help = 'Pretend that current UTC time is N (YYYYMMDDhhmmss), also enable additional control messages.')
	args = parser.parse_args()

	if args.mem <= 0:
		exit('--mem must be > 0')
	max_storage = args.mem

	if args.current_time != None:
		try:
			utc_now = datetime.strptime(args.current_time, '%Y%m%d%H%M%S').replace(tzinfo = timezone.utc)
		except Exception as e:
			exit("Couldn't parse current-time: " + str(e))

	asyncio.run(server(args))
