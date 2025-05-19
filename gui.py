import tkinter as tk
from tkinter import messagebox, filedialog
import stegano
import vpn_client
import threading
import os
from PIL import Image
from scapy.all import sniff, IP, conf

# --- GLOBAL ---
sniffing_active = False
sniffing_thread_instance = None

# Dummy credentials (ubah sesuai kebutuhan)
VALID_USERNAME = "admin"
VALID_PASSWORD = "password123"

# ---------------------------
# Fungsi login
# ---------------------------
def try_login():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    try:
        with open("login.txt", "r") as f:
            for line in f:
                if ':' not in line:
                    continue
                user, passw = line.strip().split(":", 1)
                if user == username and passw == password:
                    log_to_gui("[+] Login berhasil.")
                    login_window.destroy()
                    open_main_window()
                    return
        # Jika tidak ada yang cocok
        messagebox.showerror("Login gagal", "Username atau password salah.")
        entry_password.delete(0, tk.END)

    except FileNotFoundError:
        messagebox.showerror("Error", "File login.txt tidak ditemukan.")
    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan saat membaca file login.txt: {e}")


# ---------------------------
# Fungsi untuk log di GUI utama
# ---------------------------
def log_to_gui(message):
    if 'log_text' in globals():
        log_text.config(state='normal')
        log_text.insert(tk.END, message + "\n")
        log_text.see(tk.END)
        log_text.config(state='disabled')

# ---------------------------
# Fungsi GUI utama
# ---------------------------
def hide_data_gui():
    path = filedialog.askopenfilename(title="Pilih gambar untuk disisipkan pesan")
    if not path:
        return
    message = entry_message.get()
    if not message.strip():
        messagebox.showwarning("Peringatan", "Pesan tidak boleh kosong!")
        return
    try:
        stegano.hide_data(path, message)
        log_to_gui(f"[+] Pesan disisipkan ke gambar: {os.path.basename(path)}")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal menyisipkan pesan: {e}")
        log_to_gui(f"[!] Error sisip pesan: {e}")

def reveal_data_gui():
    path = "assets/stego_image.png"
    if not os.path.exists(path):
        messagebox.showerror("Error", f"File tidak ditemukan: {path}")
        log_to_gui(f"[!] File tidak ditemukan: {path}")
        return

    try:
        message = stegano.reveal_data(path)
        label_result.config(text=f"[+] Pesan tersembunyi:\n{message}")
        log_to_gui("[+] Pesan berhasil diambil dari gambar.")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal membaca gambar: {e}")
        log_to_gui(f"[!] Error saat mengambil pesan: {e}")

def start_vpn_gui():
    path = filedialog.askopenfilename(title="Pilih file konfigurasi VPN", filetypes=[("OVPN Files", "*.ovpn")])
    if not path:
        return
    try:
        vpn_client.start_vpn(path)
        log_to_gui(f"[~] VPN dijalankan dengan file: {os.path.basename(path)}")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal menjalankan VPN: {e}")
        log_to_gui(f"[!] VPN error: {e}")

def sniffing_thread():
    global sniffing_active, sniffing_thread_instance

    def gui_packet_callback(pkt):
        if not sniffing_active:
            return
        if IP in pkt and pkt[IP].ttl < 64:
            log_to_gui(f"[!] Potensi sniffing terdeteksi dari {pkt[IP].src}")

    def run_sniff():
        sniff(
            iface=conf.iface,
            prn=gui_packet_callback,
            store=0,
            lfilter=lambda pkt: IP in pkt,
            stop_filter=lambda x: not sniffing_active
        )

    if not sniffing_active:
        sniffing_active = True
        sniffing_thread_instance = threading.Thread(target=run_sniff, daemon=True)
        sniffing_thread_instance.start()
        log_to_gui("[~] Deteksi sniffing dimulai...")
    else:
        log_to_gui("[i] Deteksi sniffing sudah berjalan.")

def stop_sniffing():
    global sniffing_active
    if sniffing_active:
        sniffing_active = False
        log_to_gui("[~] Deteksi sniffing dihentikan.")
    else:
        log_to_gui("[i] Deteksi belum dimulai.")

def clear_output():
    log_text.config(state='normal')
    log_text.delete("1.0", tk.END)
    log_text.config(state='disabled')
    label_result.config(text="Pesan tersembunyi akan ditampilkan di sini.")

def on_enter(e):
    e.widget.config(bg="#16a085")

def on_leave(e):
    e.widget.config(bg=e.widget.default_bg)

# ---------------------------
# Fungsi buka GUI utama setelah login sukses
# ---------------------------
def open_main_window():
    global root, entry_message, log_text, label_result

    root = tk.Tk()
    root.title("InvisiNet")
    root.geometry("600x700")
    root.configure(bg="#2c3e50")

    header_font = ("Helvetica", 18, "bold")
    label_font = ("Helvetica", 12)
    button_font = ("Helvetica", 10, "bold")

    header_frame = tk.Frame(root, bg="#34495e")
    header_frame.pack(fill="x", padx=10, pady=15)
    header_label = tk.Label(header_frame, text="InvisiNet", bg="#34495e", fg="white", font=header_font)
    header_label.pack(padx=10, pady=10)

    input_frame = tk.Frame(root, bg="#2c3e50")
    input_frame.pack(fill="x", padx=20, pady=10)

    entry_label = tk.Label(input_frame, text="Pesan untuk disisipkan:", bg="#2c3e50", fg="white", font=label_font)
    entry_label.grid(row=0, column=0, sticky="w", pady=(0,5))

    entry_message = tk.Entry(input_frame, width=50, font=label_font)
    entry_message.grid(row=1, column=0, padx=5, pady=5)
    entry_message.focus_set()

    button_frame = tk.Frame(root, bg="#2c3e50")
    button_frame.pack(fill="x", padx=20, pady=10)

    btn_specs = [
        ("Sisipkan Pesan ke Gambar", hide_data_gui, "#1abc9c"),
        ("Ambil Pesan dari Gambar", reveal_data_gui, "#3498db"),
        ("Jalankan VPN", start_vpn_gui, "#9b59b6"),
        ("Deteksi Sniffing", sniffing_thread, "#e67e22"),
        ("Stop Deteksi Sniffing", stop_sniffing, "#e74c3c"),
        ("Clear Log dan Pesan", clear_output, "#95a5a6"),
    ]

    buttons = []
    for i, (text, cmd, color) in enumerate(btn_specs):
        btn = tk.Button(button_frame, text=text, command=cmd, font=button_font, bg=color, fg="white", relief="flat")
        btn.grid(row=i//2, column=i%2, padx=5, pady=6, sticky="ew")
        btn.default_bg = color
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        buttons.append(btn)

    for i in range(2):
        button_frame.grid_columnconfigure(i, weight=1)

    log_frame = tk.Frame(root, bg="#2c3e50")
    log_frame.pack(fill="both", padx=20, pady=10, expand=True)

    log_scrollbar = tk.Scrollbar(log_frame)
    log_scrollbar.pack(side="right", fill="y")

    log_text = tk.Text(log_frame, height=8, width=65, state='disabled', font=("Courier", 10), yscrollcommand=log_scrollbar.set)
    log_text.pack(fill="both", expand=True, padx=5, pady=5)

    log_scrollbar.config(command=log_text.yview)

    result_frame = tk.Frame(root, bg="#2c3e50")
    result_frame.pack(fill="x", padx=20, pady=10)

    label_result = tk.Label(result_frame, text="Pesan tersembunyi akan ditampilkan di sini.",
                            wraplength=550, justify="left", bg="#2c3e50", fg="white", font=label_font)
    label_result.pack(pady=5)

    root.mainloop()

# ---------------------------
# Setup window login
# ---------------------------
login_window = tk.Tk()
login_window.title("Login InvisiNet")
login_window.geometry("350x200")
login_window.configure(bg="#2c3e50")

label_font = ("Helvetica", 12)
entry_font = ("Helvetica", 12)

frame_login = tk.Frame(login_window, bg="#2c3e50")
frame_login.pack(expand=True)

label_title = tk.Label(frame_login, text="Login InvisiNet", bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
label_title.grid(row=0, column=0, columnspan=2, pady=(10, 15))

label_username = tk.Label(frame_login, text="Username:", bg="#2c3e50", fg="white", font=label_font)
label_username.grid(row=1, column=0, sticky="e", padx=5, pady=5)

entry_username = tk.Entry(frame_login, font=entry_font)
entry_username.grid(row=1, column=1, padx=5, pady=5)
entry_username.focus_set()

label_password = tk.Label(frame_login, text="Password:", bg="#2c3e50", fg="white", font=label_font)
label_password.grid(row=2, column=0, sticky="e", padx=5, pady=5)

entry_password = tk.Entry(frame_login, font=entry_font, show="*")
entry_password.grid(row=2, column=1, padx=5, pady=5)

btn_login = tk.Button(frame_login, text="Login", command=try_login, font=("Helvetica", 11, "bold"),
                      bg="#1abc9c", fg="white", relief="flat", width=10)
btn_login.grid(row=3, column=0, columnspan=2, pady=15)

def on_enter_login(e):
    e.widget.config(bg="#16a085")
def on_leave_login(e):
    e.widget.config(bg="#1abc9c")

btn_login.bind("<Enter>", on_enter_login)
btn_login.bind("<Leave>", on_leave_login)

login_window.mainloop()
