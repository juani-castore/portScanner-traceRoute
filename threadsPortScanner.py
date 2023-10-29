from scapy.all import *
import sys
import matplotlib.pyplot as plt

respuestas = []
srcPort = 8080



results = "portScanner_"

def sendPayload(ipDst, port, ackRes):
    # agrego el payload al paquete
    packet = IP(dst= ipDst)/TCP(flags="A", sport = srcPort , dport = port, seq=1, ack=ackRes+1 )/Raw(load="holaMundo")
    resp = sr1(packet, timeout = 1)
    if resp:
        if resp[TCP].flags == "A":
            return True
        else:
            return False
    else:
        return False


def scanPort(ipDst, port, version):
    packet = IP(dst= ipDst)/TCP(flags="A", sport = srcPort , dport = port)/Raw(load="holaMundo")
    resp = sr1(packet, timeout = 1)
    if resp:
        if resp[TCP].flags == "SA":
            if version == "-f":
                ackRes = resp[TCP].seq
                ## envio un segundo mensaje con payload y chequeo si me lo ackea
                if sendPayload(ipDst, port, ackRes):
                    respuestas.append((port, "(abierto)"))
                    return
                else:
                    respuestas.append((port, "(cerrado)"))
                    return
            elif version == "-h":
                respuestas.append((port, "(abierto)"))
                return
        elif resp[TCP].flags == "RA":
            respuestas.append((port, "(cerrado)"))
            return
        else:
            respuestas.append((port, "(raro)"))
            return
    else: 
        respuestas.append((port, "(filtrado)"))
        return

def portScanner(ipDst, version):
    # las hago globales por los hilos
    
    filtrados = 0
    abiertos = 0
    port = 1

    with open(results + str(ipDst) + ".csv", 'w') as file:
        file.write("puerto,estado\n")
    ## creo la lista de threads
    threads = []
    i = 0
    ## genero de a 100 threads, por temas de recursos
    ## se puede cambiar el numero de threads a gusto del usuario
    while i < 1000:
        ##creo un thread por puerto a analizar
        for port in range(1 + i, 100 + i):
            # cada thread ejecuta la funcion scanPort
            t = threading.Thread(target=scanPort, args=(ipDst, port, version))
            threads.append(t)
        # inicio los threads
        for t in threads:
            t.start()
        # espero a que terminen
        for t in threads:
            t.join()
        # limpio la lista
        threads.clear()
        # incrementador de a 100
        i += 100
    ## escribo los resultados en el archivo
    with open(results + str(ipDst) + ".csv", 'w') as file:
        for portResult in respuestas:
            file.write(str(portResult[0]) + "," + portResult[1] + "\n")
            if portResult[1] == "(abierto)":
                abiertos += 1
            elif portResult[1] == "(filtrado)":
                filtrados += 1
    print("porcentaje puertos abiertos: " + str((abiertos/1000)*100) + " %")
    print("porcentaje puertos filtrados: " + str((filtrados/1000)*100) + " %")
    print("porcentaje de perdidas: " + str(((1000 - abiertos - filtrados)/1000)*100) + " %")
    ### DESCOMENTAR PARA GENERAR EL GRAFICO
    ## NO SUELE DAR MUCHA INFORMACION
    #plt.pie([abiertos/100, (100 - abiertos - filtrados)/100],filtrados/100, labels=["abiertos", "cerrados", "filtrados"], autopct='%1.1f%%', shadow=True, startangle=90)
    #plt.title("Porcentaje de puertos abiertos, filtrados y cerrados")
    #plt.axis('equal')
    #plt.legend([abiertos/100, filtrados/100, (100 - abiertos - filtrados)/100], title='Categorías', loc='center left', bbox_to_anchor=(1, 0.5))
    #plt.savefig(results + str(ipDst) + ".png")


# MAIN
# Verifico que se haya ingresado la direccion ip de destino correctamente
if len(sys.argv) != 3:
    print("Uso: python portScanner.py <direccionIpDst> <-version (-h / -f)>")
    sys.exit(1)

# Guardo la direccion ip de destino
direccionTest = sys.argv[1]
portScanner(direccionTest, sys.argv[2])