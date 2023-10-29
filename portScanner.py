from scapy.all import *
import sys
#import matplotlib.pyplot as plt



results = "portScanner_"

# funcion para enviar un paquete con payload
def sendPayload(ipDst, port, ackRes):
    # agrego el payload al paquete
    packet = IP(dst= ipDst)/TCP(flags="A", sport = 8080 , dport = port, ack=ackRes+1 )/Raw(load="holaMundo")
    resp = sr1(packet, timeout = 0.1)
    # chequeo si me llego un ack del payload
    if resp:
        if resp[TCP].flags == "A":
            return True
        else:
            return False
    else:
        return False


# funcion para escanear un puerto
def scanPort(ipDst, port, version):
    # envio un paquete con el flag SYN
    packet = IP(dst= ipDst)/TCP(flags="S", sport = 8080, seq=1, dport = port)
    resp = sr1(packet, timeout = 0.1)
    if resp:
        # si recibo un paquete con el flag SYN/ACK
        if resp[TCP].flags == "SA":
            # si la version es -f envio un paquete con payload para chequear si esta abierto el puerto
            if version == "-f":
                ## envio un segundo mensaje con payload y chequeo si me lo ackea
                ackRes = resp[TCP].seq
                if sendPayload(ipDst, port, ackRes):
                    return (port, "(abierto)")
                else:
                    return (port, "(cerrado)")  
            # si la version es -h no envio el payload y lo tomo como abierto
            elif version == "-h":
                return (port, "(abierto)")
        # si recibo un paquete con el flag RST/ACK lo tomo como cerrado
        elif resp[TCP].flags == "RA":
            return (port, "(cerrado)")
        # caso en el que recibo un paquete con otro flag que no tome en cuenta
        else:
            return (port, "(raro)")
    # si no recibo nada lo tomo como filtrado
    else: 
        return (port, "(filtrado)")

# funcion para escanear los primeros 1000 puertos de una ip
def portScanner(ipDst, version):
    filtrados = 0
    abiertos = 0
    port = 1
    # abro el archivo para escribir los resultados de todos los puertos
    with open(results + str(ipDst) + ".csv", 'w') as file:
        # columnas del csv
        file.write("puerto,estado\n")
        while port <= 1000:
            portResult = scanPort(ipDst, port, version)
            # appendeo el resultado al csv como puerto,estado
            file.write(str(portResult[0]) + "," + portResult[1] + "\n")
            # cuento los puertos abiertos y filtrados
            if portResult[1] == "(abierto)":
                abiertos += 1
            elif portResult[1] == "(filtrado)":
                filtrados += 1
            port += 1
        # imprimo los porcentajes de puertos abiertos y filtrados
        print("porcentaje puertos abiertos: " + str((abiertos/1000)*100) + " %")
        print("porcentaje puertos filtrados: " + str((filtrados/1000)*100) + " %")
    
    # abro el archivo para escribir los porcentajes de puertos abiertos y filtrados
    with open("porcentajesPuertos.csv", 'a') as file:
        # aca recorto el nombre del archivo
        # asi solo se appendea la url
        file.write(ipDst +","+ str((abiertos/1000)*100) +","+ str((filtrados/1000)*100) + str( (1000 - abiertos - filtrados)/1000 * 100))

        ### DESCOMENTAR PARA GENERAR EL GRAFICO
        ## NO SUELE DAR MUCHA INFORMACION
        #plt.pie([abiertos/1000, filtrados/1000, (1000 - abiertos - filtrados)/1000],explode=(0.1, 0.1, 0.1), startangle=180, autopct='%1.0f%%',labeldistance=3.0, colors=[ '#87CEEB','#FFC0CB', '#98FB98'])
        #plt.title("Porcentaje de puertos abiertos, filtrados y cerrados")
        #plt.legend(["abiertos", "filtrados","cerrados"], title='Estados', loc='lower center', bbox_to_anchor=(1, 0.5))
        #plt.axis('equal')
        #plt.savefig(results + str(ipDst) + ".png")



# MAIN
# Verifico que se haya ingresado la direccion ip de destino correctamente
if len(sys.argv) != 3:
    print("Uso: python portScanner.py <direccionIpDst> <-version (-h / -f)>")
    sys.exit(1)

# Guardo la direccion ip de destino
direccionTest = sys.argv[1]

portScanner(direccionTest, sys.argv[2])

# 80 y 443 son los puertos mas comunes abiertos ya que son los puertos de http y https respectivamente