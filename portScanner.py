from scapy.all import *
import sys


results = "resultsPortScanner.txt"

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



def portScanner(ipDst, version):
    filtrados = 0
    abiertos = 0
    puertosAbiertos = []
    port = 1
    with open(results, 'w') as file:
        file.write("Resumen del escaneo de puertos del ip: " + ipDst + "\n")
        while port <= 1000:
            packet = IP(dst= ipDst)/TCP(flags="S", dport = port)
            resp = sr1(packet, timeout = 0.1)
            if resp:
                if resp[TCP].flags == "SA":
                    if version == "-f":
                        ## envio un segundo mensaje con payload y chequeo si me lo ackea
                        if sendPayload(ipDst, port):
                            abiertos += 1
                            file.write("puerto: " + str(port) + " (abierto)\n")
                        else:
                            file.write("puerto: " + str(port) + " (cerrado)\n")  
                    elif version == "-h":
                        abiertos += 1
                        file.write("puerto: " + str(port) + " (abierto)\n")
                elif resp[TCP].flags == "RA":
                    file.write("puerto: " + str(port) + " (cerrado)\n")
                else:
                    file.write("puerto: " + str(port) + " (raro)\n")
                    print("port: "+ str(port) +"respondio pero no sabemos que")
            else: 
                filtrados += 1
                file.write("puerto: " + str(port) + " (filtrado)\n")
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