#! /usr/bin/env python3
'''
Peer to peer instant messenger using http for gui and communication.

Copyright 2025, 2026 Ilja Honkonen

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
from os.path import dirname, join, realpath
from random import randint

import requests
from quart import jsonify, Quart, render_template, request, redirect

from messages import Message_v0
from message_stores import Message_Store_v0
from peers import Peers


async def pow_updater(args, message_store):
	update_min = max(1, args.update_pow - int(0.1 * args.update_pow))
	update_max = max(update_min + 1, args.update_pow + int(0.1 * args.update_pow))
	while True:
		await message_store.update_worst_pow()
		await asyncio.sleep(randint(update_min, update_max))


# TODO: deal with each peer concurrently
async def msg_getter(args, message_store, peers):
	while True:
		if len(peers) > 0:
			worst_current_pow, worst_pow_initially = message_store.get_worst_pow()
			for i in range(len(peers)):
				peer = peers[i]
				if not peer.should_connect():
					continue
				try:
					# fetch peer list
					peers_url = join(peer.url, 'peers')
					peers_result = requests.get(peers_url, timeout = 5)
					for line in peers_result.text.split('\n'):
						line = line.strip()
						if line == '':
							continue
						if line.endswith(args.comm_addr + ':' + str(args.comm_port)):
							continue
						skip = False
						for j in range(len(peers)):
							if line == peers[j].url:
								skip = True
								break
						if not skip:
							await peers.add(line)
							# TODO better control of peer list spamming
							break

					ids_to_send = await message_store.get_initial_pows()
					# fetch messages
					ids_url = join(peer.url, 'ids')
					ids_result = requests.get(ids_url, timeout = 5)
					received = 0
					for line in ids_result.text.split('\n'):
						line = line.strip()
						if line == '':
							continue
						initial_pow = int(line)
						if await message_store.have_message(initial_pow):
							ids_to_send.discard(initial_pow)
							continue
						get_url = join(peer.url, join('get', str(initial_pow)))
						get_result = requests.get(get_url, timeout = 5)
						for line in get_result.text.split('\n'):
							msg = Message_v0()
							if msg.parse(line, worst_current_pow) != '':
								continue
							_ = await message_store.add(msg)
							received += 1
					#print('Received', received, 'messages from', peer.url)

					# send messages not received
					sent = 0
					for id_to_send in ids_to_send:
						put_url = join(peer.url, join('put', str(id_to_send)))
						_ = requests.get(put_url, timeout = 5)
						sent += 1
					#print('Sent', sent, 'messages to', peer.url)

					peer.reset_interval() # assume everything fine now

				except BaseException as e:
					peer.update_interval(1.5)
					# TODO: show peer connection error in index.html
					#print('Error while communicating with peer {}: {}, new interval {} s' \
					#	.format(peer.url, str(e), peer.interval))
					if peer.interval > args.drop_peer:
						peer.disable()
				if peer:
					peer.update_next()

		await asyncio.sleep(1)


template_dir = join(dirname(realpath(__file__)), 'server2')
ui_app = Quart('user interface', template_folder = template_dir)
comm_app = Quart('communication')


@ui_app.get('/')
@ui_app.get('/index.html')
async def index_get():
	message_store = comm_app.extensions['message_store']
	initial_pows = await message_store.get_initial_pows()
	messages = []
	for initial_pow in initial_pows:
		message = await message_store.get_message(initial_pow)
		if message == None:
			continue
		messages.append({
			'checksum': message.checksum,
			'nonce': message.nonce,
			'payload': message.payload,
			'pow': message.current_pow,
			'timestamp': message.timestamp_str
		})
	try:
		key = request.args.get('sort')
		if key != None:
			messages.sort(key = lambda x: x[key])
	except:
		pass

	peer_store = comm_app.extensions['peers']
	peers = []
	utc_now = datetime.now(timezone.utc)
	for i in range(len(peer_store)):
		if not peer_store[i]:
			continue
		next_attempt = (peer_store[i].next_attempt - utc_now).total_seconds()
		peers.append({
			'url': peer_store[i].url,
			'next_attempt': '{:.1f} s'.format(next_attempt)
		})
	peers.sort(key = lambda x: x['url'])

	template_path = 'index.html'
	return await render_template(
		template_path, messages = messages, peers = peers,
		maxlength = Message_v0.max_payload_bytes)


@ui_app.post('/')
@ui_app.post('/index.html')
async def index_post():
	message_store = comm_app.extensions['message_store']
	worst_current_pow, worst_pow_initially = message_store.get_worst_pow()
	target_pow = worst_current_pow // 2

	peer_store = comm_app.extensions['peers']

	form = await request.form
	if 'send' in form:
		try:
			message = Message_v0()
			message.set_timestamp()
			message.set_payload(form['send'])
			message.update_nonce(target_pow)
			result = await message_store.add(message)
			if result != '':
				print("Couldn't send message:", result, flush = True)
		except BaseException as e:
			print('Unexpected error:', e)
	if 'add' in form:
		try:
			await peer_store.add(form['add'])
		except BaseException as e:
			pass

	target = request.path
	if len(request.args) > 0:
		target += '?'
		for arg in request.args:
			target += arg + '=' + request.args.get(arg)
	return redirect(target)


@comm_app.get('/ids')
async def comm_ids():
	initial_pows = await comm_app.extensions['message_store'].get_initial_pows()
	ret_val = ''
	for initial_pow in initial_pows:
		ret_val += str(initial_pow) + '\n'
	return ret_val


@comm_app.get('/get/<int:initial_pow>')
async def comm_get(initial_pow):
	message_store = comm_app.extensions['message_store']
	message = await message_store.get_message(initial_pow)
	if message == None:
		return '\n'
	else:
		return str(message) + '\n'


@comm_app.get('/put/<string:msg_str>')
async def comm_put(msg_str):
	message_store = comm_app.extensions['message_store']
	worst_current_pow, worst_pow_initially = message_store.get_worst_pow()

	msg = Message_v0()
	result = msg.parse(msg_str, worst_current_pow)
	if result != '':
		return result

	result = await message_store.add(msg)
	if result != '':
		return result
	return 'ok\n'


@comm_app.get('/peers')
async def comm_peers():
	peer_store = comm_app.extensions['peers']
	ret_val = ''
	for i in range(len(peer_store)):
		if peer_store[i]:
			ret_val += peer_store[i].url + '\n'
	return ret_val


async def main(args):
	message_store = Message_Store_v0(Message_v0.worst_pow)
	await message_store.set_max_storage(args.mem)

	ui_app.extensions['message_store'] = message_store
	comm_app.extensions['message_store'] = message_store

	peers = Peers()
	peers.set_interval(args.peer_interval)
	ui_app.extensions['peers'] = peers
	comm_app.extensions['peers'] = peers
	for peer in args.peers.split(','):
		peer = peer.strip()
		if peer == '':
			continue

		no_http = True
		no_port = True
		if peer.startswith('http'):
			no_http = False
		if \
			(':/' in peer and peer.count(':') > 1) \
			or (not ':/' in peer and peer.count(':') > 0) \
		:
			no_port = False
		if no_http or no_port:
			print('Warning: peer', peer, 'seems to be missing ', end = '')
		if no_http and no_port:
			print('protocol and port')
		elif no_http:
			print('protocol')
		elif no_port:
			print('port')
		await peers.add(peer)

	shutdown = asyncio.Event()
	ui_task = asyncio.create_task(ui_app.run_task(
		host = args.ui_addr, port = args.ui_port, shutdown_trigger = lambda: shutdown.wait()))
	comm_task = asyncio.create_task(comm_app.run_task(
		host = args.comm_addr, port = args.comm_port, shutdown_trigger = lambda: shutdown.wait()))
	msg_getter_task = asyncio.create_task(msg_getter(args, message_store, peers))
	pow_updater_task = asyncio.create_task(pow_updater(args, message_store))

	print('Serving user interface on {}:{} and p2p communication on {}:{}'\
		.format(args.ui_addr, args.ui_port, args.comm_addr, args.comm_port))

	try:
		await asyncio.gather(
			ui_task, comm_task, msg_getter_task,
			pow_updater_task, return_exceptions = True)
	finally:
		shutdown.set()
		ui_task.cancel()
		comm_task.cancel()
		msg_getter_task.cancel()
		pow_updater_task.cancel()
		await asyncio.gather(
			ui_task, comm_task, msg_getter_task,
			pow_updater_task, return_exceptions = True)


if __name__ == '__main__':
	parser = ArgumentParser(
		formatter_class = ArgumentDefaultsHelpFormatter
	)
	parser.add_argument('--mem', metavar = 'M', type = int, default = 2**8,
		help = 'Store at most M bytes of messages.')
	parser.add_argument('--ui-addr', metavar = 'A', type = str, default = '127.0.0.1',
		help = 'Serve user interface on address A.')
	parser.add_argument('--ui-port', metavar = 'P', type = int, default = 8000,
		help = 'Serve user interface on port P.')
	parser.add_argument('--comm-addr', metavar = 'B', type = str, default = '127.0.0.1',
		help = 'Serve p2p messages on address B.')
	parser.add_argument('--comm-port', metavar = 'Q', type = int, default = 6000,
		help = 'Serve p2p messages on port Q.')
	parser.add_argument('--peers', metavar = 'P', type = str, default = '',
		help = 'Connect to peers given by comma separated list of URLs '
			+ '(for example http://127.0.0.2:6000,http://127.0.0.3:6000).')
	parser.add_argument('--peer-interval', metavar = 'I', type = int, default = 20,
		help = 'Try to communicate with peer(s) every I seconds, '
			+ 'failure multiplies I by 1.5.')
	parser.add_argument('--drop-peer', metavar = 'D', type = int, default = 60,
		help = 'Drop peer if communication interval exceeds D seconds.')
	parser.add_argument('--update-pow', metavar = 'U', type = int, default = 10,
		help = "Update messages' proof of work approximately every U seconds.")
	parser.add_argument('--current-time', metavar = 'T', type = str, default = None,
		help = 'Pretend that current UTC time is T (YYYYMMDDhhmmss).')
	args = parser.parse_args()

	if args.mem < 1:
		exit('--mem cannot be < 1')

	if args.update_pow < 1:
		exit('--update-pow cannot be < 1')

	if args.current_time != None:
		try:
			utc_now = datetime.strptime(args.current_time,
				'%Y%m%d%H%M%S').replace(tzinfo = timezone.utc)
		except Exception as e:
			exit("Couldn't parse current-time: " + str(e))

	try:
		asyncio.run(main(args))
	except BaseException as e:
		print(e)
