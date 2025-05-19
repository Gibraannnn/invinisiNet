from scapy.all import sniff, IP, conf

def detect_sniffing():
    def packet_callback(pkt):
        if IP in pkt and pkt[IP].ttl < 64:
            print(f"[!] Potensi sniffing terdeteksi dari {pkt[IP].src}")
    
    # Pakai Layer 3 sniffing sebagai alternatif
    sniff(
        iface=conf.iface,             # Interface default
        prn=packet_callback,          # Callback fungsi
        store=0,                      # Tidak simpan paket
        lfilter=lambda pkt: IP in pkt  # Filter Python, bukan BPF
    )
