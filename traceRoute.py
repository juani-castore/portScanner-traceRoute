from scapy.all import *
import sys
import time


# calculador de promedios}
## crea un csv con los resultados del traceRoute en la carpeta traceroutes_obs
## filename: nombre del archivo a calcular
## tambien calcula el promedio de los tiempos de RTT y lo appendea en el archivo porcentajesRouters.csv
def calculate_mean(filename):
    mean = 0
    meanTiempos = 0
    with open("traceroutes_obs/" + filename, 'r') as f:
        lines = f.readlines()
        # saco el header
        lines.pop(0)
        for line in lines:
            line = line.split(",")
            meanTiempos += float(line[2])
            # incrementamos 1 por cada router que si responde
            if line[1] != "*":
                mean += 1    
        # calculamos el promedio de routers que nos contestaron en el camino
        mean = (mean/len(lines))*100 
        # calculamos el promedio de los tiempos de RTT de todos los hops
        meanTiempos = meanTiempos/len(lines)           
    
    with open("porcentajesRouters.csv", 'a') as file:
        # aca recorto el nombre del archivo
        # asi solo se apendea la url
        file.write(filename[10:len(filename)-4] + "," +str(mean)+ "," + str(meanTiempos) + "\n")
        print("promedio mensajes TTL0 recibidos: " + str(mean))
        print("promedio tiempos de RTT de todos los hops: " + str(meanTiempos))






## FUNCIONES ## definimos el traceRoute
def traceRoute(direccionIpDst):
    results = "traceRoute" + direccionIpDst + ".csv"
    timeSnd = 0
    timeRcv = 0
    ttl = 1
    # el flag indica cuando llegamos a destino
    flag = True
    
    # obtengo la direccion ip de destino
    direccionIpDst = socket.gethostbyname(direccionIpDst)


    with open("traceroutes_obs/" + results, 'w') as file:
        # columnas del csv
        file.write("ttl,ip,RTT\n")
        while flag:
            packet = IP(dst= direccionIpDst, ttl = ttl)/ICMP(type=8, code=0)
            # time agregado para calcular el tiempo de RTT
            timeSnd = time.time()
            resp = sr1(packet, timeout = 0.5)
            timeRcv = time.time()
        
            ip = "*"
            # chequeo si tengo un ip para escribir en el csv
            if (resp is not None):
                ip = str(resp.src)
            # escribo en el csv el ttl, ip y el tiempo de RTT
            file.write(str(ttl) + "," + ip + "," + str(timeRcv-timeSnd) + "\n")

            if resp is None:
                print("***")
                ttl += 1
            elif resp.src == direccionIpDst:
                print("destino alcanzado en " + str(ttl) + " saltos y con RTT de: " + str(timeRcv - timeSnd) + " segundos")
                flag = False
            else:
                #print(ttl)
                print(resp.src)
                ttl += 1
    calculate_mean(results)




## MAIN ##
# Verifico que se haya ingresado la direccion ip de destino correctamente
if len(sys.argv) != 2:
    print("Uso: python traceRoute.py <direccionIpDst>")
    sys.exit(1)

# Guardo la direccion ip de destino
direccionTest = sys.argv[1]

# ejecuto el traceRoute 1 vez
#traceRoute(direccionTest)

# ejecuto el traceRoute 30 veces
i = 0
while i < 30:
    traceRoute(direccionTest)
    i += 1