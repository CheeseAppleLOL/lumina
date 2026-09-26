import sys
import os
import json
import struct
import subprocess
import platform

def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length or len(raw_length) < 4:
        return None
    message_length = struct.unpack('@I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode('utf-8')
    return json.loads(message)

def send_message(message_content):
    encoded_content = json.dumps(message_content).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('@I', len(encoded_content)))
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()

def sanitize_and_route(payload):
    if not isinstance(payload, dict):
        return {"status": "error", "message": "Invalid JSON root type. Expected object."}

    action = payload.get("action")
    if not action:
        return {"status": "error", "message": "Missing required field: 'action'"}

    if action == "ping":
        return {"status": "success", "message": "Lumina native host responsive", "platform": platform.system()}

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, ".."))
    driver_script = os.path.join(repo_root, ".agents", "skills", "run-lumina", "driver.py")

    if not os.path.isfile(driver_script):
        return {"status": "error", "message": f"Driver script not found at {driver_script}"}

    try:
        process = subprocess.Popen(
            [sys.executable, driver_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(input=json.dumps(payload), timeout=15)
        return {"status": "success", "output": stdout.strip(), "error": stderr.strip()}
    except subprocess.TimeoutExpired:
        process.kill()
        return {"status": "error", "message": "Native driver execution timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    if sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    while True:
        try:
            msg = read_message()
            if msg is None:
                break
            response = sanitize_and_route(msg)
            send_message(response)
        except Exception as e:
            send_message({"status": "error", "message": f"Unhandled host error: {str(e)}"})
            break
