from scapy.all import *
import sys
import time


## FUNCIONES ## definimos el traceRoute
def traceRoute(direccionIpDst):
    timeSnd = 0
    timeRcv = 0
    ttl = 1
    flag = True

    direccionIpDst = socket.gethostbyname(direccionIpDst)
    while flag:
        packet = IP(dst= direccionIpDst, ttl = ttl)/ICMP(type=8, code=0)
        # time agregado para calcular el tiempo de respuesta
        timeSnd = time.time()
        resp = sr1(packet, timeout = 10)
        timeRcv = time.time()
        if resp is None:
            print("***")
            ttl += 1
        elif resp.src == direccionIpDst:
            print("destino alcanzado en " + str(ttl) + " saltos y " + str(timeRcv - timeSnd) + " segundos")
            flag = False
        else:
            #print(ttl)
            print(resp.src)
            ttl += 1


## MAIN ##
# Verifico que se haya ingresado la direccion ip de destino correctamente
if len(sys.argv) != 2:
    print("Uso: python traceRoute.py <direccionIpDst>")
    sys.exit(1)

# Guardo la direccion ip de destino
direccionTest = sys.argv[1]

traceRoute(direccionTest)
        