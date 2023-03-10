import socket
from common_ports import ports_and_services
from socket import gethostbyname, gaierror, herror
import re


def portScanner(ip_addr, port_range):
  open_ports = []
  for port in range(port_range[0], port_range[1] + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((ip_addr, port))
    if result == 0:
      if (ports_and_services.get(port)):
        open_ports.append(port)
    s.close()
  return open_ports


def get_open_ports(target, port_range, verbose=False):
  try:
    if (re.search(r"[0-9]", target)):
      host = socket.gethostbyaddr(target)[0]
      ip_addr = target
    else:
      ip_addr = socket.gethostbyname(target)
      host = target
    open_ports = portScanner(ip_addr, port_range)
    if (verbose):
      text = 'Open ports for ' + host + ' (' + ip_addr + ')\nPORT     SERVICE\n'
      k = 0
      for port in open_ports:
        service = str(ports_and_services.get(port))
        port = str(port)
        space = 9 - len(port) + len(service)
        k += 1
        if (k < len(open_ports)):
          text = text + port + service.rjust(space, " ") + '\n'
        else:
          text = text + port + service.rjust(space, " ")
      return text
    else:
      return open_ports
  except gaierror:
    if (re.match(r"[0-9]", target)):
      return ("Error: Invalid IP address")
    else:
      return ("Error: Invalid hostname")
  except herror:
    open_ports = portScanner(target, port_range)
    if (verbose):
      text = 'Open ports for ' + target + '\nPORT     SERVICE\n'
      k = 0
      for port in open_ports:
        service = str(ports_and_services.get(port))
        port = str(port)
        space = 9 - len(port) + len(service)
        k += 1
        if (k < len(open_ports)):
          text = text + port + service.rjust(space, " ") + '\n'
        else:
          text = text + port + service.rjust(space, " ")
        return text
      else:
        return open_ports
