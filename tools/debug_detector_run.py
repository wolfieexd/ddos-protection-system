import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.ddos_detector import DDoSDetector, TrafficMetrics
import time

D = DDoSDetector(time_window=10, requests_threshold=5)
for i in range(10):
    m = TrafficMetrics(timestamp=time.time(), ip_address='10.0.0.1', user_agent='x', endpoint='/', method='GET', status_code=200, response_time=0.1, payload_size=0)
    # simulate the usual flow: analyze_traffic appends buffer and ip_request_count
    is_attack, sig = D.analyze_traffic(m)
    thr = D._adaptive_threshold()
    recent = [ts for ts in D.ip_request_count[m.ip_address] if time.time() - ts <= D.time_window]
    print(i+1, 'recent_len=', len(recent), 'threshold=', thr, 'is_blocked=', D.is_blocked('10.0.0.1'), 'is_attack=', is_attack)
    if is_attack:
        print('DETECTED at', i+1)
        break
print('blocked?', D.is_blocked('10.0.0.1'))
