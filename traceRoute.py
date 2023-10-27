from scapy.all import *
import sys
import time


# calculador de promedios
def calculate_mean(filename):
    mean = 0
    with open("traceroutes_obs/" + filename, 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = line.split(",")
            # incrementamos 1 por cada router que si responde
            if line[1] != "*":
                mean += 1    
        # calculamos el promedio de routers que nos contestaron en el camino
        mean = (mean/len(lines))*100            
    
    with open("porcentajesRouters.csv", 'a') as file:
        # aca recorto el nombre del archivo
        # asi solo se apendea la url
        file.write(filename[10:len(filename)-4] + "," +str(mean)+ "\n")
        print("promedio: " + str(mean))
    






## FUNCIONES ## definimos el traceRoute
def traceRoute(direccionIpDst):
    results = "traceRoute" + direccionIpDst + ".csv"
    timeSnd = 0
    timeRcv = 0
    ttl = 1
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
            resp = sr1(packet, timeout = 1)
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
                print("destino alcanzado en " + str(ttl) + " saltos y " + str(timeRcv - timeSnd) + " segundos")
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

traceRoute(direccionTest)
        