import cmd
import logging
import os
import subprocess
import tempfile
import threading
import time
import json
import re

import proxy
import history
import intercept
import fuzzer
from http_parser import HTTPRequest, HTTPResponse

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
            choice = input("(F)orward, (D)rop, (E)dit, (S)can, (Z)Fuzz, or forward (A)ll? [f/d/e/s/z/a]: ").strip().lower()
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
            elif choice == 's':
                import scanner
                host, port = proxy._http_target(item.request)
                protocol = "https" if port == 443 else "http"
                findings = scanner.scan_directories(host=host, port=port, protocol=protocol)
                scanner.print_findings(findings)
            elif choice == 'z':
                host, port = proxy._http_target(item.request)
                protocol = "https" if port == 443 else "http"
                self._interactive_fuzz(item.request, host, port, protocol)
                # Notice no 'break' here! After the fuzzer runs, the prompt returns
                # so you can still Forward or Drop the original intercepted request.
            elif choice == 'a':
                intercept.engine.forward(item.id)
                intercept.engine.enabled = False
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
    def _interactive_fuzz(self, item_req: HTTPRequest, host: str, port: int, protocol: str):
        """Opens the request in an editor to let the user place a FUZZ marker, then runs the fuzzer."""
        print("\n[*] Opening request in editor. Replace the exact target value with the word 'FUZZ' (all caps).")
        print("[*] Example: Cookie: session=FUZZ")
        input("Press Enter to open editor...")

        editor = os.environ.get('EDITOR', 'notepad' if os.name == 'nt' else 'nano')
        with tempfile.NamedTemporaryFile(suffix=".http", delete=False) as tf:
            tf.write(item_req.to_bytes())
            tmp_name = tf.name

        subprocess.call([editor, tmp_name])

        with open(tmp_name, 'rb') as f:
            template_bytes = f.read()
        os.unlink(tmp_name)

        if b"FUZZ" not in template_bytes:
            print("[-] Marker 'FUZZ' not found in the edited request. Aborting fuzzer.")
            return

        print(f"[*] 'FUZZ' marker found! Starting fuzzer against {host}...")
        
        # 1. Establish Baseline using the ORIGINAL request
        try:
            baselineResp, baselineTime = fuzzer.sendRequest(item_req, host, port, protocol)
        except Exception as e:
            print(f"[-] Baseline request failed: {e}")
            return
            
        results = []
        payloads = fuzzer.DEFAULT_PAYLOADS 
        
        print(f"[*] Testing {len(payloads)} payloads...")
        for payload in payloads:
            # 2. Mutate raw bytes exactly where the user placed 'FUZZ'
            mutated_bytes = template_bytes.replace(b"FUZZ", payload.encode('utf-8'))
            
            # 3. Fix Content-Length safely BEFORE parsing so payloads don't get truncated
            header_part, sep, body_part = mutated_bytes.partition(b"\r\n\r\n")
            if body_part and b"Content-Length:" in header_part:
                header_text = header_part.decode('utf-8', errors='replace')
                header_text = re.sub(r'(?i)Content-Length:\s*\d+', f'Content-Length: {len(body_part)}', header_text)
                mutated_bytes = header_text.encode('utf-8') + sep + body_part

            # 4. Parse the newly mutated bytes and send
            try:
                mutated_req = HTTPRequest.from_bytes(mutated_bytes)
                fuzzResp, fuzzTime = fuzzer.sendRequest(mutated_req, host, port, protocol)
                
                # 5. Diff against baseline
                anomalies, errorMatches = fuzzer.checkAnomalies(
                    baselineResp, baselineTime, fuzzResp, fuzzTime
                )
                
                if anomalies:
                    results.append(fuzzer.FuzzResult(
                        injectionPoint="Custom 'FUZZ' marker",
                        payload=payload,
                        baselineStatus=baselineResp.status_code,
                        fuzzStatus=fuzzResp.status_code,
                        baselineLength=len(baselineResp.body or b""),
                        fuzzLength=len(fuzzResp.body or b""),
                        baselineTime=baselineTime,
                        fuzzTime=fuzzTime,
                        anomalies=anomalies,
                        errorMatches=errorMatches,
                    ))
            except Exception:
                pass # Drop silent on network failures for individual fuzz requests
                
        fuzzer.printResults(results)

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

    def do_scan(self, arg):
        """scan <id> [--dir] : Run vulnerability scanners on a captured request/response.
        Use --dir to also run the active directory fuzzer against the host."""
        import scanner 
        
        args = arg.split()
        if not args or not args[0].isdigit():
            print("Usage: scan <id> [--dir]")
            return
            
        flow_id = int(args[0])
        run_dir_scan = "--dir" in args
        
        row = history.getFlow(flow_id)
        
        if not row or not row["resp_status"]:
            print(f"Flow {flow_id} not found, or it doesn't have a response to scan.")
            return

        # Reconstruct the response object for passive scanning
        raw_headers = json.loads(row["resp_headers"])
        headers = {k.lower(): v for k, v in raw_headers}
        resp = HTTPResponse(
            version=row["resp_version"],
            status_code=row["resp_status"],
            reason=row["resp_reason"],
            headers=headers,
            raw_headers=raw_headers,
            body=row["resp_body"] or b""
        )

        findings = []
        
        # 1. Run passive scanners (analyzing the captured traffic)
        print("[*] Running passive scanners...")
        findings.extend(scanner.scan_headers(resp))
        findings.extend(scanner.scan_sensitive_data(resp))
        
        # 2. Run active scanners (sending new traffic)
        if run_dir_scan:
            findings.extend(scanner.scan_directories(
                host=row["host"],
                port=row["port"],
                protocol=row["protocol"]
            ))
        
        scanner.print_findings(findings)
    def do_fuzz(self, arg):
        """fuzz <id> [wordlist] : Automatically fuzz all parameters, JSON fields, and headers of a historical request.
        Examples:
          fuzz 12
          fuzz 12 payloads/sqli.txt
        """
        args = arg.split()
        if not args or not args[0].isdigit():
            print("Usage: fuzz <id> [wordlist.txt]")
            return
            
        flow_id = int(args[0])
        wordlist_path = args[1] if len(args) > 1 else None
        
        try:
            payloads = fuzzer.DEFAULT_PAYLOADS
            if wordlist_path:
                print(f"[*] Loading custom wordlist from {wordlist_path}...")
                payloads = fuzzer.loadWordlist(wordlist_path)
                
            print(f"[*] Starting automated semantic fuzzer on flow {flow_id}...")
            
            # This calls the powerful automated fuzzer you built in fuzzer.py!
            results = fuzzer.fuzzFlow(flow_id, payloads=payloads)
            fuzzer.printResults(results)
            
        except FileNotFoundError:
            print(f"[-] Wordlist not found: {wordlist_path}")
        except ValueError as e:
            print(f"[-] Error: {e}")
        except Exception as e:
            print(f"[-] Fuzzer failed: {e}")

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