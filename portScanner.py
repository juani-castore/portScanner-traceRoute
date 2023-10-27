from scapy.all import *
import sys
#import matplotlib.pyplot as plt



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
        
    with open("porcentajesPuertos.csv", 'a') as file:
        # aca recorto el nombre del archivo
        # asi solo se apendea la url
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

# 80 y 443 deberian estar abiertos en google.com