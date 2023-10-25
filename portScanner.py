from scapy.all import *
import sys


results = "portScanner_"

def sendPayload(ipDst, port):
    # agrego el payload al paquete
    packet = IP(dst= ipDst)/TCP(flags="A", dport = port)/Raw(load="holaMundo")
    resp = sr1(packet, timeout = 0.1)
    if resp:
        if resp[TCP].flags == "A":
            return True
        else:
            return False
    else:
        return False






from scapy.all import *
import sys

results = "portScanner_"

def sendPayload(ipDst, port):
    # agrego el payload al paquete
    packet = IP(dst= ipDst)/TCP(flags="A", dport = port)/Raw(load="holaMundo")
    resp = sr1(packet, timeout = 0.1)
    if resp:
        if resp[TCP].flags == "A":
            return True
        else:
            return False
    else:
        return False

def scanPort(ipDst, port, version):
    packet = IP(dst= ipDst)/TCP(flags="S", dport = port)
    resp = sr1(packet, timeout = 0.1)
    if resp:
        if resp[TCP].flags == "SA":
            if version == "-f":
                ## envio un segundo mensaje con payload y chequeo si me lo ackea
                if sendPayload(ipDst, port):
                    return (port, "(abierto)")
                else:
                    return (port, "(cerrado)")  
            elif version == "-h":
                return (port, "(abierto)")
        elif resp[TCP].flags == "RA":
            return (port, "(cerrado)")
        else:
            return (port, "(raro)")
    else: 
        return (port, "(filtrado)")

def portScanner(ipDst, version):
    filtrados = 0
    abiertos = 0
    puertosAbiertos = []
    port = 1
    with open(results + str(ipDst) + ".csv", 'w') as file:
        file.write("puerto,estado\n")
        while port <= 1000:
            portResult = scanPort(ipDst, port, version)
            file.write(str(portResult[0]) + "," + portResult[1] + "\n")
            if portResult[1] == "(abierto)":
                abiertos += 1
            elif portResult[1] == "(filtrado)":
                filtrados += 1
            port += 1
        print("porcentaje puertos abiertos: " + str((abiertos/1000)*100) + " %")
        print("porcentaje puertos filtrados: " + str((filtrados/1000)*100) + " %")

# MAIN
# Verifico que se haya ingresado la direccion ip de destino correctamente
if len(sys.argv) != 3:
    print("Uso: python portScanner.py <direccionIpDst> <-version (-h / -f)>")
    sys.exit(1)

# Guardo la direccion ip de destino
direccionTest = sys.argv[1]
portScanner(direccionTest, sys.argv[2])

# 53 y 443 deberian estar abiertos