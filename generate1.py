#! /usr/bin/env python3
'''
Generates p2pIM message(s) to stdout.

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
from datetime import datetime, timedelta, timezone
from sys import argv

from messages import Message_v0

if __name__ == '__main__':
	parser = ArgumentParser(
		formatter_class = ArgumentDefaultsHelpFormatter
	)
	parser.add_argument('message', type = str, metavar = 'M',
		nargs = '*', default = ['__info__'], help = 'Print message M.')
	parser.add_argument('--current-time', metavar = 'N', type = str,
		default = None, help = 'Pretend that current UTC time'
		+ ' is N (YYYYMMDDhhmmss).')
	parser.add_argument('--message-time', metavar = 'T', type = str,
		default = None, help = 'Create messages with timestamp'
		+ ' T (YYYYMMDDhhmmss).')
	parser.add_argument('--pow', metavar = 'W', type = str,
		default = 'f' * Message_v0.pow_bytes,
		help = 'Use proof of work of at most distance W from target'
		+ ' (' + Message_v0.pow_target.to_bytes(
			length = Message_v0.pow_bytes//2).hex() + ')'
		+ ', interpreted as hex, allowed range '
		+ '0' * Message_v0.pow_bytes + '..'
		+ 'f' * Message_v0.pow_bytes + '.')
	parser.add_argument('--duration', metavar = 'D', type = int,
		default = 10, help = 'Aim for message duration of'
		+ ' approximately D seconds.')
	parser.add_argument('--debug', action = 'store_true', default = False)
	args = parser.parse_args()

	if args.duration <= 0:
		exit('Message duration must be > 0')
	args.duration = timedelta(seconds = args.duration)

	try:
		args.pow = int(args.pow, 16)
	except Exception as e:
		print("Couldn't parse minimum proof of work:", e)
		exit(1)

	if args.current_time != None:
		try:
			args.current_time = datetime.strptime(args.current_time, '%Y%m%d%H%M%S').replace(tzinfo = timezone.utc)
		except Exception as e:
			exit("Couldn't parse current-time: " + str(e))
	if args.message_time != None:
		try:
			args.message_time = datetime.strptime(args.message_time, '%Y%m%d%H%M%S').replace(tzinfo = timezone.utc)
		except Exception as e:
			exit("Couldn't parse current-time: " + str(e))

	age = max(args.duration, Message_v0.min_message_age) / Message_v0.min_message_age
	args.pow = int(args.pow / age)

	message = Message_v0()

	for payload in args.message:
		current_time = datetime.now(timezone.utc)
		if args.current_time != None:
			current_time = args.current_time
		message_time = datetime.now(timezone.utc)
		if args.message_time != None:
			message_time = args.message_time

		message.set_timestamp(message_time)
		message.set_payload(payload)
		message.update_nonce(args.pow, current_time)
		print(message, end = '')
		if args.debug:
			ipow = message.initial_pow.to_bytes(length = message.pow_bytes//2).hex()
			cpow = message.current_pow.to_bytes(length = message.pow_bytes//2).hex()
			print(', init PoW:', ipow, ' current PoW:', cpow, end = '')
		print()
