#!/usr/bin/python3
#
# A simple sample app with USDT.
# Please follow https://github.com/sthima/python-stapsdt to install dependencies.
import stapsdt
import http.server
import socketserver
from urllib import parse

# Add a USDT probe.
provider = stapsdt.Provider("simple_app")
probe = provider.add_probe("sum", stapsdt.ArgTypes.int32, stapsdt.ArgTypes.int32)
provider.load()


class MyHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        query = parse.parse_qs(parse.urlparse(self.path).query)
        a = int(query.get("a", [1])[0])
        b = int(query.get("b", [2])[0])
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(str(sum(a, b)).encode())


def sum(a, b):
    probe.fire(a, b)
    return a + b


if __name__ == "__main__":
    my_server = socketserver.TCPServer(("", 8080), MyHTTPHandler)
    my_server.allow_reuse_address = True
    my_server.serve_forever()
