import os, sys
import socket
from datetime import datetime

whois = 'whois.internic.net'
domain = sys.argv[1]

def getResponse(domain):
  whois = 'whois.internic.net'
  s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
  s.connect((whois , 43))

  domain += '\r\n'
  byt = domain.encode()
  s.send(byt)

  response = ''
  while len(response) < 10000:
    chunk = s.recv(100)
    chunk = chunk.decode()
    if(chunk == ''):
      break
    response = response + chunk
  return response

def getExpiryDate(response):
  lines = response.splitlines()
  for line in lines:
    line = line.lstrip().rstrip()
    if ":" in line:
      info = line.split(':')
      if "Registry Expiry Date" in info:
        s = ':'.join(info[1:]).lstrip()
        f = "%Y-%m-%dT%H:%M:%S%fZ"
        out = datetime.strptime(s, f)
        return out


def getResult(domain):
  domain = domain.replace('http://','')
  domain = domain.replace('www.','')
  ext = domain[-3:]

  if(ext == 'com' or ext == 'org' or ext == 'net'):
    response = getResponse(domain)
    expiryDate = getExpiryDate(response)
    return expiryDate
  return None

print(getResult(domain))