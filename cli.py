import cmd
import logging
import os
import subprocess
import tempfile
import threading
import time
import json

import proxy
import history
import intercept
import fuzzer
from http_parser import HTTPRequest

# Force all proxy logs into a file instead of the terminal!
logging.basicConfig(
    filename='proxy_debug.log',
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    force=True 
)

class ProxyCLI(cmd.Cmd):
    intro = "\n=== MITM Proxy CLI ===\nType 'help' or '?' to list commands.\n"
    prompt = "(proxy) "

    def __init__(self):
        super().__init__()
        # Start proxy in the background
        self.proxy_thread = threading.Thread(target=proxy.start_proxy, daemon=True)
        self.proxy_thread.start()
        time.sleep(0.5) # Give proxy a moment to bind to the port

    # --- Live Traffic Feed ---
    
    def do_live(self, arg):
        """live [host] : Stream live traffic. Press Ctrl+C to stop. Optional: filter by host."""
        print("Streaming live traffic... Press Ctrl+C to stop.")
        # Find the current highest ID so we only stream new requests
        row = history.connection().execute("SELECT MAX(id) FROM flows").fetchone()
        last_id = row[0] if row[0] is not None else 0
        
        try:
            while True:
                rows = history.connection().execute(
                    "SELECT id, req_method, host, req_path, resp_status FROM flows WHERE id > ? ORDER BY id ASC", 
                    (last_id,)
                ).fetchall()
                
                for r in rows:
                    if arg and arg.lower() not in r["host"].lower():
                        last_id = r["id"]
                        continue
                    
                    path = r["req_path"][:30] + "..." if len(r["req_path"]) > 30 else r["req_path"]
                    print(f"[{r['id']}] {r['req_method']:<6} {r['host']:<25} {path:<35} -> {r['resp_status'] or '---'}")
                    last_id = r["id"]
                
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\nStopped live feed.")

    # --- Intercept Engine Controls ---

    def do_intercept(self, arg):
        """intercept [on|off] [host=<glob>] [path=<glob>] [method=<GET|POST>]
        Examples: 
          intercept on host=*amazon* path=*toy*
          intercept on method=POST
          intercept on *downloadmoreram.com (legacy shorthand for host)
        """
        args = arg.split()
        if not args:
            state = "ON" if intercept.engine.enabled else "OFF"
            print(f"Intercept is currently {state}.")
            return

        command = args[0].lower()
        
        if command == "on":
            intercept.engine.clear_rules() # Clear old rules
            
            if len(args) > 1:
                kwargs = {}
                # Parse advanced arguments like host=... path=... method=...
                for param in args[1:]:
                    if "=" in param:
                        key, val = param.split("=", 1)
                        if key == "host": kwargs["host_pattern"] = val
                        elif key == "path": kwargs["path_pattern"] = val
                        elif key == "method": kwargs["methods"] = {val.upper()}
                
                # If they used kwargs, apply them
                if kwargs:
                    intercept.engine.add_rule(intercept.InterceptRule(**kwargs))
                    print(f"[+] Intercept mode ON. Rules applied: {kwargs}")
                # Fallback for the old shorthand (e.g. `intercept on *amazon.com`)
                else:
                    host_pattern = args[1]
                    intercept.engine.add_rule(intercept.InterceptRule(host_pattern=host_pattern))
                    print(f"[+] Intercept mode ON. Only targeting host: {host_pattern}")
            else:
                print("[!] Intercept mode ON for ALL traffic. (Warning: This will be very noisy!)")
                
            intercept.engine.enabled = True
            
        elif command == "off":
            intercept.engine.enabled = False
            print("[-] Intercept mode OFF. Traffic flows freely.")

    def do_queue(self, arg):
        """queue : Check how many intercepted requests are waiting."""
        count = intercept.engine.pending_request_count()
        print(f"There are currently {count} requests waiting in the queue.")

    def do_flush(self, arg):
        """flush : Instantly forward all currently queued requests."""
        count = 0
        try:
            while True:
                item = next(intercept.engine.pending_requests(block=False))
                intercept.engine.forward(item.id)
                count += 1
        except StopIteration:
            pass
        print(f"[+] Flushed {count} requests from the queue.")

    def do_step(self, arg):
        """step : Fetch the next intercepted request and decide to forward, drop, or edit it."""
        try:
            # Grab the next request without blocking indefinitely
            item = next(intercept.engine.pending_requests(block=False))
        except StopIteration:
            print("Queue is empty. No pending requests.")
            return

        print("\n--- Intercepted Request ---")
        print(item.request.to_bytes().decode('utf-8', errors='replace'))
        print("---------------------------\n")

        while True:
            choice = input("(F)orward, (D)rop, (E)dit, or forward (A)ll? [f/d/e/a]: ").strip().lower()
            if choice == 'f':
                intercept.engine.forward(item.id)
                print("[+] Forwarded.")
                break
            elif choice == 'd':
                intercept.engine.drop(item.id)
                print("[-] Dropped.")
                break
            elif choice == 'e':
                modified_req = self._edit_request(item.request)
                if modified_req:
                    intercept.engine.modify_request(item.id, modified_req)
                    print("[+] Forwarded modified request.")
                else:
                    print("[!] Edit cancelled or invalid. Forwarding original request.")
                    intercept.engine.forward(item.id)
                break
            elif choice == 'a':
                # 1. Forward the current item
                intercept.engine.forward(item.id)
                # 2. Turn off the intercept engine so no new requests get caught
                intercept.engine.enabled = False
                # 3. Flush whatever else is already sitting in the queue
                self.do_flush("") 
                print("[+] Intercept turned OFF. All pending requests forwarded.")
                break

    def _edit_request(self, req: HTTPRequest) -> HTTPRequest | None:
        """Helper function to open the request in the user's default text editor."""
        editor = os.environ.get('EDITOR', 'notepad' if os.name == 'nt' else 'nano')
        
        with tempfile.NamedTemporaryFile(suffix=".http", delete=False) as tf:
            tf.write(req.to_bytes())
            tmp_name = tf.name

        subprocess.call([editor, tmp_name])

        with open(tmp_name, 'rb') as f:
            data = f.read()
        os.unlink(tmp_name)

        try:
            return HTTPRequest.from_bytes(data)
        except Exception as e:
            print(f"Error parsing modified request: {e}")
            return None

    # --- History and Replay ---

    def do_history(self, arg):
        """history [host=<host>] [status=<status>] : View recently logged requests."""
        host_filter = None
        status_filter = None
        
        for param in arg.split():
            if param.startswith("host="):
                host_filter = param.split("=")[1]
            elif param.startswith("status="):
                status_filter = int(param.split("=")[1])

        rows = history.search(host=host_filter, status_code=status_filter, limit=15)
        if not rows:
            print("No records found.")
            return

        print(f"{'ID':<5} | {'METHOD':<6} | {'HOST':<25} | {'STATUS':<6} | {'PATH'}")
        print("-" * 80)
        for r in rows:
            path = r['req_path'][:30] + "..." if len(r['req_path']) > 30 else r['req_path']
            print(f"{r['id']:<5} | {r['req_method']:<6} | {r['host']:<25} | {r['resp_status'] or '---':<6} | {path}")

    def do_replay(self, arg):
        """replay <id> : Replay a specific request from the history database."""
        if not arg.isdigit():
            print("Usage: replay <id>")
            return
            
        flow_id = int(arg)
        row = history.getFlow(flow_id)
        if not row:
            print(f"Flow {flow_id} not found in database.")
            return

        # Reconstruct the request from the database row
        raw_headers = json.loads(row["req_headers"])
        headers = {k.lower(): v for k, v in raw_headers}
        req = HTTPRequest(
            method=row["req_method"],
            path=row["req_path"],
            version=row["req_version"],
            headers=headers,
            raw_headers=raw_headers,
            body=row["req_body"] or b""
        )

        print(f"Replaying {req.method} request to {row['host']}...")
        try:
            # We can reuse the sendRequest method you built for the fuzzer!
            resp, t = fuzzer.sendRequest(req, row['host'], row['port'], row['protocol'])
            print(f"[+] Received Status {resp.status_code} in {t:.2f} seconds.")
            print(f"[+] Body Size: {len(resp.body or b'')} bytes.")
        except Exception as e:
            print(f"[-] Replay failed: {e}")

    # --- Utilities ---

    def do_exit(self, arg):
        """exit : Shut down the proxy and exit the CLI."""
        print("Shutting down...")
        
        os._exit(0)  # Instantly kills all threads and releases the port
        
    def do_EOF(self, arg):
        return self.do_exit(arg)

if __name__ == '__main__':
    try:
        ProxyCLI().cmdloop()
    except KeyboardInterrupt:
        print("\n[+] Caught Ctrl+C. Shutting down proxy cleanly...")
        
        os._exit(0)  # Instantly kills all threads and releases the port