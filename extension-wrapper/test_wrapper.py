import sys
import os
import json
import struct
import subprocess

def test_native_wrapper():
    wrapper_path = os.path.join(os.path.dirname(__file__), "lumina_host.py")
    
    payload = json.dumps({"action": "ping"}).encode("utf-8")
    header = struct.pack("@I", len(payload))
    
    proc = subprocess.Popen(
        [sys.executable, wrapper_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    stdout_data, stderr_data = proc.communicate(input=header + payload, timeout=5)
    
    resp_len = struct.unpack("@I", stdout_data[:4])[0]
    resp_body = json.loads(stdout_data[4:4+resp_len].decode("utf-8"))
    
    assert resp_body.get("status") == "success", f"Test failed: {resp_body}"
    assert resp_body.get("message") == "Lumina native host responsive"
    print("SUCCESS: Native Messaging Wrapper framing and response verified!")

if __name__ == "__main__":
    test_native_wrapper()
