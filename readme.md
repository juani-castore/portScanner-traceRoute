# Proyecto de Análisis de Redes

## Materia: Redes de Computación
En este proyecto, he implementado dos herramientas: Traceroute y un Port Scanner, utilizando Python y Scapy.

## Traceroute

Traceroute es una herramienta que permite mapear la ruta entre un host origen y un host remoto, mostrando el tiempo de ida y vuelta (RTT) de los paquetes a lo largo de la ruta.

### Implementación de Traceroute

Para la implementación de Traceroute, aproveché el campo TTL (time-to-live) de los paquetes IP. Envié una serie de paquetes IP con TTL incrementado. Cuando los hosts intermedios respondieron con mensajes de error, obtuve las direcciones IP de los hosts intermedios.

## Port Scanner

El Port Scanner es una herramienta para analizar el estado de los puertos en un host, basado en el protocolo TCP y el 3-way handshake.

### Implementación del Port Scanner

Implementé un Port Scanner que realiza un escaneo de los puertos menores a 1000 en un host. Consideré los puertos abiertos aquellos en los que el host respondía con un SYN-ACK. Los resultados se guardan en un archivo de texto.

### Port Scanner Extendido

También extendí el Port Scanner para considerar un segundo parámetro que controla el tipo de escaneo. "-h" para el escaneo básico (SYN-ACK) y "-f" para un escaneo que verifica una conexión TCP completa.


