from abc import ABC, abstractmethod
import asyncio

class ProtocolBase(ABC):
	@staticmethod
	@abstractmethod
	async def from_streamreader(reader):
		"""
		this method needs to be decorated with @asyncio.coroutine
		"""
		raise NotImplementedError

	@staticmethod
	async def from_bytes(bbuff):
		"""
		takes bytes, returns the instentiated class
		"""
		raise NotImplementedError

	@staticmethod
	@abstractmethod
	def from_buffer(buff):
		"""
		takes io.BytesIO, returns the instentiated class
		"""
		raise NotImplementedError

	@abstractmethod
	def construct():
		raise NotImplementedError

	@abstractmethod
	def to_bytes(self):
		"""
		serializes the class
		"""
		raise NotImplementedError
