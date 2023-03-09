import socket
import nmap

scanner=nmap.PortScanner()

def get_open_ports(target, port_range):
    scanner.scan(target,''+str(port_range[0])+'-'+ str(port_range[1])+'','-v -sS')
    open_ports=scanner[target]['tcp'].keys()
    return(open_ports)

