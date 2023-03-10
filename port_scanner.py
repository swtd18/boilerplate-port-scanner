import socket
import nmap
from common_ports import ports_and_services
from socket import gethostbyname, gaierror,herror
import re

scanner=nmap.PortScanner()

def get_open_ports(target, port_range,verbose=False):
    try:
        if(re.search(r"[0-9]",target)):
            host=socket.gethostbyaddr(target)[0]
            ip_addr=target
        else :
            ip_addr=socket.gethostbyname(target)
            host=target
        scanner.scan(ip_addr,''+str(port_range[0])+'-'+ str(port_range[1])+'','-v -sS')
        open_ports=scanner[ip_addr]['tcp'].keys()
        known_open_ports=[]
        for port in open_ports:
            if(ports_and_services.get(port)):
                known_open_ports.append(port)     
        if(verbose):
            text='Open ports for '+host+' ('+ip_addr+')\nPORT     SERVICE\n'
            k=0
            for port in known_open_ports :
                service=str(ports_and_services.get(port))
                port=str(port)
                space=9-len(port)+len(service)
                k+=1
                if(k<len(known_open_ports)):
                    text=text+port + service.rjust(space," ")+'\n'
                else:
                    text=text+port + service.rjust(space," ")
            return text
        else:
            return known_open_ports
    except gaierror:
        if(re.match(r"[0-9]",target)):
            return("Error: Invalid IP address")
        else:
            return("Error: Invalid hostname")
    except herror:
        try:
            scanner.scan(target,''+str(port_range[0])+'-'+ str(port_range[1])+'','-v -sS')
            open_ports=scanner[target]['tcp'].keys()
            known_open_ports=[]
            for port in open_ports:
                if(ports_and_services.get(port)):
                    known_open_ports.append(port)     
            if(verbose):
                text='Open ports for '+target+'\nPORT     SERVICE\n'
                k=0
                for port in known_open_ports :
                    service=str(ports_and_services.get(port))
                    port=str(port)
                    space=9-len(port)+len(service)
                    k+=1
                    if(k<len(known_open_ports)):
                        text=text+port + service.rjust(space," ")+'\n'
                    else:
                        text=text+port + service.rjust(space," ")
                return text
            else :
                known_open_ports=[]  
        except Exception as err:
            return(f"Unexpected {err=}")
    except Exception as err:
        return(f"Unexpected {err=}")
   
