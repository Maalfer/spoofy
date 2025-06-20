# 🔥 DNS & ARP Spoofing Tool - MITM Attack GUI

Una herramienta de ataque Man-in-the-Middle (MITM) con interfaz gráfica, desarrollada en Python y basada en Scapy y Tkinter. Permite realizar ataques de ARP Spoofing, DNS Spoofing y bloqueo de red a una víctima específica dentro de una red local.

![MITM Tool Banner](https://img.shields.io/badge/status-Development-orange)  
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)  
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

---

## ✨ Funcionalidades

- 🎯 **ARP Spoofing** para interceptar tráfico entre la víctima y el gateway.
- 🧠 **DNS Spoofing** configurable: define dominios personalizados para redirigir.
- 🔇 **Bloqueo de Internet**: desactiva la conectividad de la víctima con un clic.
- 🔍 **Escaneo de red** para encontrar hosts disponibles.
- 🔐 **Intercepción de credenciales** en tráfico HTTP y FTP.
- 🌐 **Reenvío de paquetes** y NAT para mantener la conexión a Internet de la víctima.
- 🖥️ Interfaz gráfica fácil de usar con `Tkinter`.

---

## 🧪 Requisitos

- Python 3.8+
- Sistema operativo **Linux** (con permisos de root)
- Bibliotecas:
  - `scapy`
  - `netifaces`
  - `tkinter` (generalmente preinstalada en sistemas con entorno gráfico)

Instálalos con:

```bash
sudo apt update
sudo apt install python3-pip
pip3 install scapy netifaces
sudo python3 spoofy.py
```

