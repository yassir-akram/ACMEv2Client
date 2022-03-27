#!/usr/bin/env python

import argparse
import functools
from threading import Thread
import http.server
import ssl

from ACMEv2Client import * 


def main(argv):
  parser = argparse.ArgumentParser(
           formatter_class=argparse.RawDescriptionHelpFormatter,
           description="Program that automatically generate TLS certificate through ACME protocol.")
  parser.add_argument("--acme_server_dir", default="https://acme-v02.api.letsencrypt.org/directory", help="ACME server url")
  parser.add_argument("--account_key", required=False, help="path to the key used to communicate with the ACME server")
  parser.add_argument("--csr", required=False, help="path to your Certificate Signing Request")
  parser.add_argument("--http01_server_root", required=True, help="root of the http01 server")
  parser.add_argument("--no-check", default=True, action="store_false", help="check or not that the challenge is effective before validating a challenge")
  parser.add_argument("--domain", action="append", required=True, help="domain to validate")
  
  args = parser.parse_args(argv)
  
  Handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=args.http01_server_root)
  http01_server = http.server.HTTPServer(("", 8000), Handler)
  http01_server_thread = Thread(target=http01_server.serve_forever)
  http01_server.serve_forever()
  http01_server_thread.setDaemon(True)
  http01_server_thread.start() 
  
  client = Acmev2Client(acme_server_dir_url=args.acme_server_dir, 
                        server_root_dir=args.http01_server_root, 
                        account_key_path=args.account_key, 
                        check=not args.no_check)
    
  crt = client.register_domains(domains=args.domain, csr_path=args.csr)
  with open("server_cert.pem", "wt") as f:
    f.write(crt)
  http01_server.shutdown()
  """
  https_server= http.server.HTTPServer(("", 8001), http.server.BaseHTTPRequestHandler)
  https_server= http.server.HTTPServer(("", 8001), Handler)
  https_server.socket = ssl.wrap_socket(https_server.socket, 
                                        keyfile="server_privatekey.pem", 
                                        certfile="server_cert.pem", 
                                        server_side=True)
  https_server_thread = Thread(target=https_server.serve_forever)
  https_server.serve_forever()
  https_server_thread.setDaemon(True)
  https_server_thread.start()
  """
if __name__ == "__main__":
  import sys
  main(sys.argv[1:])
