#! /usr/bin/env python3

import asyncio
from datetime import datetime, timedelta, timezone
from random import randint


class Peer:
	def __init__(self, new_url = None, new_interval: int = 60):
		self.disabled = True
		self.url = None
		self.next_attempt = None
		self.default_interval = new_interval
		self.reset_interval()
		if new_url != None:
			self.set_url(new_url)

	def reset_interval(self):
		self.interval = self.default_interval

	def set_url(self, new_url):
		self.disabled = False
		self.url = new_url
		self.next_attempt = datetime.now(timezone.utc)
		self.reset_interval()

	def disable(self):
		self.disabled = True
		self.next_attempt = None
		self.reset_interval()

	def __bool__(self):
		return self.disabled != True

	def should_connect(self):
		if not self:
			return False
		if self.next_attempt > datetime.now(timezone.utc):
			return False
		return True

	def update_next(self):
		self.next_attempt = datetime.now(timezone.utc) + timedelta(seconds = self.interval)

	def update_interval(self, coeff):
		self.interval = max(1, int(self.interval * coeff))


class Peers:
	def __init__(self):
		self.lock = asyncio.Lock()
		self.default_interval = 60
		self.peers = []

	def set_interval(self, new_interval: int):
		self.default_interval = new_interval

	async def add(self, new_url):
		async with self.lock:
			self.peers.append(Peer(new_url, self.default_interval))

	def disable(self, index):
		if index >= len(self.peers):
			return
		self.peers[index].disable()

	def set_url(self, index, url):
		if index >= len(self.peers):
			return
		self.peers[index].set_url(url)

	def __getitem__(self, i):
		return self.peers[i]

	def __len__(self):
		return len(self.peers)

	def __str__(self):
		return self.__repr__()
	def __repr__(self):
		ret_val = ''
		for i in range(len(self)):
			if self[i]:
				ret_val += self[i].url + '\n'
		return ret_val


async def main():
	peers = Peers()
	await peers.add('http://localhost:8000')
	await peers.add('http://localhost:8001')
	await peers.add('http://localhost:8002')
	for i in range(len(peers)):
		peers.disable(i)
	peers[1].set_url('localhost')
	if str(peers) != 'localhost\n':
		exit('Failed')

if __name__ == '__main__':
	asyncio.run(main())
