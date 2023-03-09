import socket
import nmap
from common_ports import ports_and_services

scanner=nmap.PortScanner()

def get_open_ports(target, port_range,verbose=True):
    scanner.scan(target,''+str(port_range[0])+'-'+ str(port_range[1])+'','-v -sS')
    open_ports=scanner[target]['tcp'].keys()
    if(verbose):
        text='the  open ports for {'+target+'}are:\nPort\tService\n'
        for port in open_ports :
            text=text+str(port)+'\t'+str(ports_and_services.get(port))+'\n'
        return text
    else:
        return open_ports

