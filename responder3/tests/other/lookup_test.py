import re

proxy_fake_dest_table = {
	re.compile('alma.com'): [
		{
			range(1,500) : '127.0.0.1'
		}
	]
}

def fake_dest_lookup(dest_ip, dest_port):
		for ipregx in proxy_fake_dest_table:
			if ipregx.match(dest_ip):
				for portranged in proxy_fake_dest_table[ipregx]:
					for portrange in portranged:
						if dest_port in portrange:
							return portranged[portrange]



if __name__ == '__main__':
	print(fake_dest_lookup('alma.com', 600))