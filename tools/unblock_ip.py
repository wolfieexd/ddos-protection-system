import sys
import urllib.request

if len(sys.argv) < 2:
    print('Usage: python tools/unblock_ip.py <ip> [api_key]')
    sys.exit(2)

ip = sys.argv[1]
api_key = sys.argv[2] if len(sys.argv) > 2 else 'change-me-in-production'
url = f'http://localhost/admin/unblock/{ip}?api_key={api_key}'
req = urllib.request.Request(url, data=b'', method='POST')
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read().decode()
        print('Response:', body)
except Exception as e:
    print('Error:', e)
    sys.exit(1)
