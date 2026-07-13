import sys
import os
sys.path.append('c:/Project/XTI-SOC/project')

from online.correlation_engine import CorrelationEngine
import queue

class MockFlow:
    def __init__(self, src_ip, dst_ip, dst_port, protocol, req_server, duration_ms, bytes_):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.requested_server_name = req_server
        self.bidirectional_duration_ms = duration_ms
        self.bidirectional_bytes = bytes_

q = queue.Queue()
engine = CorrelationEngine(q)

# Test 1: Port Scan (51 distinct ports)
for port in range(1, 52):
    f = MockFlow("192.168.1.100", "10.0.0.1", port, "TCP", "", 10, 100)
    engine.add_flow(f)

# Wait, the Correlation engine processes on add_flow!
print("Queue size after port scan test:", q.qsize())
alert = q.get()
print("Alert type:", alert["attack_type"])
assert alert["attack_type"] == "Port Scan"

print("All tests passed!")
