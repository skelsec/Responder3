import asyncio
from responder3.core.manager.r3manager_server import *
import time



async def send_cmd(cmdq, manager_cmd_queue_in):
	while True:
		cmd = await cmdq.get()
		await manager_cmd_queue_in.put(cmd)

async def read_client(manager_cmd_queue_out):
	while True:
		response = await manager_cmd_queue_out.get()
		print(response)

async def read_logs(log_queue):
	while True:
		log = await log_queue.get()
		print(str(log))

async def send_commands(cmdq):
	while True:
		print('sending cmd!')
		"""
		cmd = R3CliListInterfacesCmd()
		await cmdq.put(('ALL',cmd))
		await asyncio.sleep(5)
		"""
		cmd = R3CliListServersCmd()
		await cmdq.put(('ALL',cmd))
		await asyncio.sleep(5)

		cmd = R3CliServerStopCmd(server_id = 0)
		await cmdq.put(('ALL',cmd))
		await asyncio.sleep(5)
		"""
		cmd = R3CliShutdownCmd()
		await cmdq.put(('ALL',cmd))
		await asyncio.sleep(5)
		"""


if __name__ == '__main__':
	cmdq = asyncio.Queue()
	listen_ip = '127.0.0.1'
	listen_port = 9191
	config = {}
	manager_shutdown_evt = asyncio.Event()
	log_queue = asyncio.Queue()
	manager_cmd_queue_in = asyncio.Queue()
	manager_cmd_queue_out = asyncio.Queue()
	manager_task = Responder3ManagerServer(listen_ip, listen_port, config, log_queue, log_queue, manager_cmd_queue_in, manager_cmd_queue_out, manager_shutdown_evt)
	
	asyncio.ensure_future(read_logs(log_queue))
	asyncio.ensure_future(send_commands(cmdq))
	asyncio.ensure_future(read_client(manager_cmd_queue_out))
	asyncio.ensure_future(send_cmd(cmdq, manager_cmd_queue_in))
	asyncio.ensure_future(manager_task.run())



	asyncio.get_event_loop().run_forever()

	time.sleep(10000)
	print('Done!')