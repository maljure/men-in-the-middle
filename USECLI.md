# Using the MITM Proxy CLI

This document explains how to use our interactive command-line interface for the proxy. The CLI allows you to watch traffic, intercept requests, edit them on the fly, and replay past requests.

## Getting Started

Start the proxy by running:
`python cli.py`

**Note:** The proxy runs in the background. All background errors and connection logs are automatically routed to `proxy_debug.log` so they don't interrupt your typing.

Type `help` or `?` at any time to see a list of commands.

---

## Passive Monitoring

* **`live`**
  Streams live traffic directly to your terminal. Press `Ctrl+C` to stop watching and return to the prompt.
  * *Example:* `live`
  * *Example:* `live google.com` (Only stream traffic containing 'google.com')

* **`history`**
  View the last 15 logged requests from the SQLite database.
  * *Example:* `history`
  * *Example:* `history host=amazon.com status=404`

* **`replay <id>`**
  Instantly resend a request from the history database to the server.
  * *Example:* `replay 24`

---

## Intercepting & Editing Traffic

The intercept engine allows you to pause requests before they leave your computer so you can drop, forward, or modify them.

### 1. Set your Intercept Rules
Don't intercept everything (it will break your browser). Use filters to target exactly what you want:
* `intercept on` (Intercepts EVERYTHING - not recommended)
* `intercept on *amazon.com` (Intercepts all traffic to Amazon)
* `intercept on host=*amazon* path=*toy* method=POST` (Highly targeted)
* `intercept off` (Turns interception off and lets traffic flow normally)

### 2. Handle the Queue
Once interception is ON, matching requests will be paused in a queue.
* **`queue`**: See how many requests are currently paused.
* **`step`**: Pulls the next request from the queue so you can handle it.
* **`flush`**: Instantly forwards everything in the queue (useful if you got bogged down with junk requests).

### 3. The `step` Command Options
When you type `step`, the proxy will show you the raw request and ask what you want to do:
`[F]orward, [D]rop, [E]dit, or forward [A]ll?`

* **F (Forward)**: Send the request to the server exactly as it is.
* **D (Drop)**: Kill the request. The server will never see it.
* **E (Edit)**: Opens the request in your default text editor (e.g., Notepad). 
  * *Workflow:* Make your changes -> **Save the file** -> **Close the window**. The proxy will automatically forward your modified request. *(Note: If you change the length of a POST body, remember to update the `Content-Length` header!)*
* **A (All)**: Forwards the current request, turns intercept `OFF`, and flushes the rest of the queue. Use this when you are done and want the page to finish loading normally.

---

## Exiting

* **`exit`** (or `Ctrl+C`): Instantly shuts down the proxy server and exits the CLI.

*(Note: Your traffic history is saved in `history.db`. It does not delete itself upon exiting. If you want a fresh database, manually delete `history.db` before starting the proxy).*