import matplotlib.pyplot as plt

with open("porcentajesRouters.csv", 'r') as file:
    lines = file.readlines()
    archivos = []
    porcentajes = []
    header = lines.pop(0)
    for line in lines:
        line = line.split(",")
        archivos.append(line[0])
        porcentajes.append(float(line[1]))
    plt.bar(archivos, porcentajes)
    plt.xticks(rotation=90)
    plt.xlabel("archivos")
    plt.ylabel("porcentaje de routers")
    plt.title("porcentaje de routers por archivo")
    plt.savefig("porcentajesRouters.jpeg")
    plt.show()


