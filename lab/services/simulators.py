"""Protocol simulators: no execution, authentication, files or stored input."""
import argparse
import socketserver
import threading


class FTP(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        self.wfile.write(b"220 SmartHack FTP simulator - dummy input only\r\n")
        try:
            for _ in range(20):
                line = self.rfile.readline(512)
                if not line:
                    break
                verb = line.split(None, 1)[0].upper() if line.strip() else b""
                reply = {
                    b"USER": b"331 Dummy password required",
                    b"PASS": b"530 Login disabled in simulator",
                    b"SYST": b"215 UNIX Type: L8",
                    b"FEAT": b"211 No extensions",
                    b"AUTH": b"502 TLS unavailable in lab simulator",
                    b"QUIT": b"221 Goodbye",
                }.get(verb, b"502 Not implemented")
                self.wfile.write(reply + b"\r\n")
                if verb == b"QUIT":
                    break
        except (OSError, TimeoutError):
            pass


class Telnet(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            self.request.sendall(
                b"\xff\xfb\x01\xff\xfb\x03\r\nSmartHack Telnet simulator\r\n"
                b"No shell. Dummy input only.\r\nlogin: "
            )
            self.request.recv(512)
            self.request.sendall(b"\r\nLogin disabled. Goodbye.\r\n")
        except (OSError, TimeoutError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    args = parser.parse_args()
    servers = [Server((args.bind, port), handler)
               for port, handler in ((2121, FTP), (2323, Telnet))]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("FTP simulator :2121; Telnet simulator :2323; Ctrl+C to stop", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()
            server.server_close()
