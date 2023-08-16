from socket import socket, timeout, gaierror, AF_INET, SOCK_STREAM
from argparse import ArgumentParser
from time import time
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
from typing import Set

TIMEOUT = 0.1
THREAD_COUNT = 16

def init_argparse() -> ArgumentParser:
	parser = ArgumentParser(
		usage='%(prog)s [OPTION]',
		description='Run a scan to check for open TCP ports on local or remote host.'
	)
	parser.add_argument('--host', '-H', default='127.0.0.1', help='Host to scan; default is 127.0.0.1 (localhost).')
	parser.add_argument('--start', '-s', type=int, default=1, help='Port to start scan on; default is 1.')
	parser.add_argument('--end', '-e', type=int, default=2 ** 16, help='Port to end scan before; default is 65536.')
	return parser


def connect(host: str, port: int) -> int:
	sock = socket(AF_INET, SOCK_STREAM)
	sock.settimeout(TIMEOUT)
	try:
		print(f'\r...Attempting port {port}', end='')
		sock.connect((host, port))
		return port
	except (ConnectionRefusedError, TimeoutError, timeout):
		return None
	except gaierror as err:
		print(f'\nFailed to connect to host with error: \'{err}\'')
		exit(1)
	finally:
		sock.close()


def scan_ports(host: str, start: int, end: int) -> Set[int]:
	open_ports = set()
	with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
		try:
			for result in executor.map(connect, repeat(host), range(start, end)):
				if result:
					open_ports.add(result)
			return open_ports
		except KeyboardInterrupt:
			executor.shutdown()
			print('\nOpen Ports:')
			for port in open_ports:
				print(port)
			print('\nExiting')
			exit(0)


def run_scan(host: str, start: int, end: int):
	print(f'Initiating scan on host \'{args.host}\'...')
	time_s = time()
	open_ports = scan_ports(host, start, end)
	time_e = time()
	total_time = timedelta(seconds=time_e - time_s)
	print(f'\rScan complete in {total_time}!', end='\n')
	if open_ports:
		print('Open ports:')
		for port in open_ports:
			print(port)


if __name__ == '__main__':
	parser = init_argparse()
	args = parser.parse_args()
	run_scan(args.host, args.start, args.end)
