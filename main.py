import os
import io
import glob
import zipfile
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Import core logic from provided files
from crypto import (
    list_users, create_user, login_user,
    import_pub_pem, export_pub_pem,
    build_payload_components, decrypt_and_verify_components,
)
from qr import generate_qr_auto_v3, collect_payload_from_qr_images

# Constants
SAFE_MAX_DENSITY = 800 
SESSION_TIMEOUT_SECONDS = 300 

class EncryptedQRApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure QR - Compatible Edition")
        self.geometry("1000x850")
        self.session = None
        self.last_activity = time.time()
        
        self.login_frame = LoginFrame(self)
        self.main_frame = MainFrame(self)
        
        self.bind_all("<Any-KeyPress>", self.reset_timer)
        self.bind_all("<Any-Button>", self.reset_timer)
        
        self.show_login()
        self.check_timeout_loop()

    def reset_timer(self, event=None):
        self.last_activity = time.time()

    def check_timeout_loop(self):
        if self.session and (time.time() - self.last_activity > SESSION_TIMEOUT_SECONDS):
            self.logout()
            messagebox.showwarning("Session Timeout", "You have been logged out due to inactivity.")
        self.after(1000, self.check_timeout_loop)

    def show_login(self):
        self.main_frame.pack_forget()
        self.login_frame.refresh_users()
        self.login_frame.pack(fill="both", expand=True)

    def show_main(self, session):
        self.session = session
        self.last_activity = time.time()
        self.login_frame.pack_forget()
        self.main_frame.load_session(session)
        self.main_frame.pack(fill="both", expand=True)

    def logout(self):
        self.session = None 
        self.main_frame.clear_all_ui()
        self.show_login()

class LoginFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.app = parent
        ttk.Label(self, text="Secure PC Login", font=("Arial", 16, "bold")).pack(pady=20)
        box = ttk.Frame(self); box.pack(pady=10)
        ttk.Label(box, text="User:").grid(row=0, column=0, padx=8, pady=8)
        self.user_var = tk.StringVar()
        self.user_combo = ttk.Combobox(box, textvariable=self.user_var, state="readonly", width=25)
        self.user_combo.grid(row=0, column=1, padx=8, pady=8)
        ttk.Label(box, text="Password:").grid(row=1, column=0, padx=8, pady=8)
        self.pw_var = tk.StringVar()
        ttk.Entry(box, textvariable=self.pw_var, show="*", width=27).grid(row=1, column=1, padx=8, pady=8)
        btns = ttk.Frame(self); btns.pack(pady=10)
        ttk.Button(btns, text="Login", command=self.login).grid(row=0, column=0, padx=8)
        ttk.Button(btns, text="Create User", command=self.create_user_popup).grid(row=0, column=1, padx=8)

    def refresh_users(self):
        users = list_users()
        self.user_combo["values"] = users
        if users: self.user_var.set(users[0])

    def login(self):
        try:
            session = login_user(self.user_var.get(), self.pw_var.get())
            self.pw_var.set(""); self.app.show_main(session)
        except Exception as e: messagebox.showerror("Login failed", str(e))

    def create_user_popup(self):
        win = tk.Toplevel(self); win.title("New User"); win.geometry("350x240"); win.grab_set()
        u, p1, p2 = tk.StringVar(), tk.StringVar(), tk.StringVar()
        ttk.Label(win, text="Username:").pack(); ttk.Entry(win, textvariable=u).pack()
        ttk.Label(win, text="Password:").pack(); ttk.Entry(win, textvariable=p1, show="*").pack()
        ttk.Label(win, text="Confirm:").pack(); ttk.Entry(win, textvariable=p2, show="*").pack()
        def create():
            if p1.get() != p2.get(): return messagebox.showerror("Error", "Passwords mismatch")
            try:
                create_user(u.get(), p1.get()); win.destroy(); self.refresh_users()
            except Exception as e: messagebox.showerror("Error", str(e))
        ttk.Button(win, text="Create", command=create).pack(pady=10)

class MainFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.app = parent
        self.session = None
        self.selected_file_paths = []
        self.last_decrypted_payload = None

        top = ttk.Frame(self); top.pack(fill="x", padx=10, pady=5)
        self.user_label = ttk.Label(top, text=""); self.user_label.pack(side="left")
        ttk.Button(top, text="Logout", command=self.app.logout).pack(side="right")

        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=5)

        self.nb = ttk.Notebook(self); self.nb.pack(fill="both", expand=True, padx=10, pady=5)
        self.tab_encrypt = ttk.Frame(self.nb)
        self.tab_decrypt = ttk.Frame(self.nb)
        self.tab_contacts = ttk.Frame(self.nb)
        self.nb.add(self.tab_encrypt, text="Encrypt & Send")
        self.nb.add(self.tab_decrypt, text="Receive & Decrypt")
        self.nb.add(self.tab_contacts, text="Contacts")

        self.build_encrypt_tab(); self.build_decrypt_tab(); self.build_contacts_tab()

    def load_session(self, session):
        self.session = session
        self.user_label.config(text=f"User: {session['username']}")
        self.clear_all_ui()
        self.refresh_contacts(); self.refresh_receivers()

    def clear_all_ui(self):
        self.text.delete("1.0", "end")
        self.log_encrypt.delete("1.0", "end")
        self.selected_file_paths = []
        self.file_label.config(text="No files selected")
        self.log_decrypt.delete("1.0", "end")
        self.last_decrypted_payload = None
        self.btn_preview.config(state="disabled")
        self.btn_save.config(state="disabled")
        self.progress["value"] = 0

    # --- ENCRYPT TAB ---
    def build_encrypt_tab(self):
        f = self.tab_encrypt
        settings = ttk.LabelFrame(f, text="QR Settings"); settings.pack(fill="x", padx=10, pady=5)
        ttk.Label(settings, text="Receiver:").grid(row=0, column=0, padx=5, pady=5)
        self.receiver_var = tk.StringVar()
        self.receiver_combo = ttk.Combobox(settings, textvariable=self.receiver_var, state="readonly")
        self.receiver_combo.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(settings, text="TTL (s):").grid(row=0, column=2, padx=5, pady=5)
        self.ttl_var = tk.StringVar(value="3600")
        ttk.Entry(settings, textvariable=self.ttl_var, width=12).grid(row=0, column=3, padx=5, pady=5)
        ttk.Label(settings, text="Density:").grid(row=1, column=0, padx=5, pady=5)
        self.chunk_var = tk.StringVar(value="700")
        ttk.Entry(settings, textvariable=self.chunk_var, width=10).grid(row=1, column=1, padx=5, pady=5)
        
        files_frame = ttk.Frame(f); files_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(files_frame, text="Add File(s)", command=self.select_files).pack(side="left", padx=5)
        ttk.Button(files_frame, text="Clear", command=self.clear_files).pack(side="left", padx=5)
        self.file_label = ttk.Label(files_frame, text="No files selected")
        self.file_label.pack(side="left", padx=5)
        
        self.text = tk.Text(f, height=8); self.text.pack(fill="x", padx=10, pady=5)
        ttk.Button(f, text="GENERATE ENCRYPTED QR SEQUENCE", command=self.start_encrypt_thread).pack(pady=10)
        self.log_encrypt = tk.Text(f, height=12); self.log_encrypt.pack(fill="both", expand=True, padx=10, pady=5)

    def select_files(self):
        paths = filedialog.askopenfilenames()
        if paths:
            self.selected_file_paths = list(paths)
            self.file_label.config(text=f"{len(paths)} files selected")

    def clear_files(self):
        self.selected_file_paths = []; self.file_label.config(text="No files selected")

    def start_encrypt_thread(self):
        threading.Thread(target=self.generate_qr_logic, daemon=True).start()

    def generate_qr_logic(self):
        self.progress["value"] = 0
        receiver = self.receiver_var.get()
        if not receiver: return messagebox.showerror("Error", "Select a receiver")
        try:
            max_chunk = int(self.chunk_var.get())
            msg_text = self.text.get("1.0", "end-1c").strip()
            if not self.selected_file_paths and not msg_text:
                return messagebox.showerror("Error", "No content to encrypt")
            
            qr_prefix = simple_prompt("Name for this QR set:") or "secure_qr"
            self.log_encrypt.insert("end", "[1/3] Packaging content...\n")
            
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                if msg_text: zf.writestr("message.txt", msg_text.encode("utf-8"))
                for path in self.selected_file_paths: zf.write(path, os.path.basename(path))
            payload = zip_buffer.getvalue()
            self.progress["value"] = 30
            
            self.log_encrypt.insert("end", "[2/3] Encrypting...\n")
            with open(os.path.join(self.session["contacts_dir"], f"{receiver}_enc_public.pem"), "rb") as f:
                receiver_pub = import_pub_pem(f.read())
            
            filename = qr_prefix if qr_prefix.lower().endswith(".zip") else f"{qr_prefix}.zip"
            comp = build_payload_components(
                plaintext_bytes=payload, receiver_pub=receiver_pub,
                sender_sign_priv=self.session["sign_priv"], mode="file",
                filename=filename, sender_id=self.session["username"],
                ttl_seconds=int(self.ttl_var.get() or "3600")
            )
            self.progress["value"] = 40
            
            out_dir = filedialog.askdirectory()
            if not out_dir: return
            self.log_encrypt.insert("end", f"[3/3] Drawing QR codes...\n")
            paths = generate_qr_auto_v3(
                comp=comp, out_dir=out_dir, max_chunk_bytes=max_chunk, 
                prefix=qr_prefix, progress_callback=lambda c, t: self.progress.configure(value=40+(c*(60/t)))
            )
            self.progress["value"] = 100
            self.log_encrypt.insert("end", f"SUCCESS: Generated {len(paths)} codes.\n")
            messagebox.showinfo("Done", f"Success! {len(paths)} QR codes generated.")
        except Exception as e: messagebox.showerror("Error", str(e))
        finally: self.progress["value"] = 0

    # --- DECRYPT TAB ---
    def build_decrypt_tab(self):
        f = self.tab_decrypt
        btn_frame = ttk.Frame(f); btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Step 1: Scan & Reassemble", command=self.start_decrypt_thread).pack(side="left", padx=5)
        self.btn_preview = ttk.Button(btn_frame, text="Step 2: Preview Message", command=self.preview_message, state="disabled")
        self.btn_preview.pack(side="left", padx=5)
        self.btn_save = ttk.Button(btn_frame, text="Step 3: Save ZIP File", command=self.save_decrypted, state="disabled")
        self.btn_save.pack(side="left", padx=5)
        self.log_decrypt = tk.Text(f, height=30); self.log_decrypt.pack(fill="both", expand=True, padx=10, pady=5)

    def start_decrypt_thread(self):
        paths = filedialog.askopenfilenames(filetypes=[("Images", "*.png *.jpg")])
        if paths: threading.Thread(target=self.decrypt_logic, args=(list(paths),), daemon=True).start()

    def decrypt_logic(self, paths):
        self.log_decrypt.insert("end", f"Scanning {len(paths)} files...\n")
        try:
            comp = collect_payload_from_qr_images(paths)
            sender_id = comp["sender_id"].decode("utf-8")
            with open(os.path.join(self.session["contacts_dir"], f"{sender_id}_sign_public.pem"), "rb") as f:
                sender_pub = import_pub_pem(f.read())
            meta, plaintext = decrypt_and_verify_components(comp, self.session["enc_priv"], sender_pub)
            self.last_decrypted_payload = plaintext
            self.suggested_name = meta.get("fn", "received.zip")
            self.log_decrypt.insert("end", f"SUCCESS: Verified data from {sender_id}.\n")
            self.btn_preview.config(state="normal")
            self.btn_save.config(state="normal")
        except Exception as e: messagebox.showerror("Failed", str(e))

    def preview_message(self):
        if not self.last_decrypted_payload: return
        try:
            with zipfile.ZipFile(io.BytesIO(self.last_decrypted_payload)) as zf:
                if "message.txt" in zf.namelist():
                    content = zf.read("message.txt").decode("utf-8")
                    win = tk.Toplevel(self); win.title("Message Preview"); win.geometry("500x400")
                    txt = tk.Text(win); txt.pack(fill="both", expand=True)
                    txt.insert("1.0", content); txt.config(state="disabled")
                else: messagebox.showinfo("Info", "No 'message.txt' found inside the archive.")
        except Exception as e: messagebox.showerror("Error", f"Could not read zip: {e}")

    def save_decrypted(self):
        if not self.last_decrypted_payload: return
        save_path = filedialog.asksaveasfilename(initialfile=self.suggested_name, defaultextension=".zip")
        if save_path:
            with open(save_path, "wb") as f: f.write(self.last_decrypted_payload)
            messagebox.showinfo("Saved", f"File saved to {save_path}")

    # --- CONTACTS TAB (Buttons Pinned to Top) ---
    def build_contacts_tab(self):
        f = self.tab_contacts
        
        # 1. PACK BUTTONS FIRST at the top
        btn_f = ttk.Frame(f)
        btn_f.pack(side="top", fill="x", pady=15)
        
        ttk.Button(btn_f, text="Import Encryption Key", 
                   command=lambda: self.import_peer("enc")).pack(side="left", padx=5)
        ttk.Button(btn_f, text="Import Signing Key", 
                   command=lambda: self.import_peer("sign")).pack(side="left", padx=5)
        ttk.Button(btn_f, text="Delete Contact", 
                   command=self.delete_contact).pack(side="left", padx=5)
        ttk.Button(btn_f, text="Export My Keys", command=self.export_my).pack(side="left", padx=5)

        # 2. PACK LOG SECOND below the buttons
        log_frame = ttk.Frame(f)
        log_frame.pack(side="top", fill="both", expand=True, padx=10, pady=5)
        
        scrollbar = ttk.Scrollbar(log_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.contacts_log = tk.Text(log_frame, height=5, yscrollcommand=scrollbar.set)
        self.contacts_log.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.contacts_log.yview)

    def refresh_contacts(self):
        self.contacts_log.config(state="normal")
        self.contacts_log.delete("1.0", "end")
        files = glob.glob(os.path.join(self.session["contacts_dir"], "*.pem"))
        for f in sorted(files):
            self.contacts_log.insert("end", os.path.basename(f) + "\n")
        self.contacts_log.config(state="disabled")

    def refresh_receivers(self):
        files = glob.glob(os.path.join(self.session["contacts_dir"], "*_enc_public.pem"))
        self.receiver_combo["values"] = [os.path.basename(f).replace("_enc_public.pem", "") for f in files]

    def import_peer(self, k_type):
        path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if not path: return
        name = simple_prompt("Contact Name:")
        if path and name:
            dst = os.path.join(self.session["contacts_dir"], f"{name}_{k_type}_public.pem")
            with open(path, "rb") as fsrc, open(dst, "wb") as fdst: 
                fdst.write(fsrc.read())
            self.refresh_contacts(); self.refresh_receivers()

    def delete_contact(self):
        name = simple_prompt("Enter Contact Name to delete:")
        if not name: return
        targets = [
            os.path.join(self.session["contacts_dir"], f"{name}_enc_public.pem"),
            os.path.join(self.session["contacts_dir"], f"{name}_sign_public.pem")
        ]
        found = False
        for t in targets:
            if os.path.exists(t):
                os.remove(t)
                found = True
        if found:
            messagebox.showinfo("Deleted", f"Keys for '{name}' removed.")
            self.refresh_contacts(); self.refresh_receivers()
        else:
            messagebox.showwarning("Not Found", f"No keys found for '{name}'.")

    def export_my(self):
        folder = filedialog.askdirectory()
        if folder:
            with open(os.path.join(folder, f"{self.session['username']}_enc_pub.pem"), "wb") as f:
                f.write(export_pub_pem(self.session["enc_pub"]))
            with open(os.path.join(folder, f"{self.session['username']}_sign_pub.pem"), "wb") as f:
                f.write(export_pub_pem(self.session["sign_pub"]))

def simple_prompt(label):
    win = tk.Toplevel(); win.title("Input"); win.geometry("300x130"); win.grab_set()
    v = tk.StringVar(); ttk.Label(win, text=label).pack(pady=10); ttk.Entry(win, textvariable=v).pack()
    def ok(): win.destroy()
    ttk.Button(win, text="OK", command=ok).pack(pady=10); win.wait_window()
    return v.get().strip()

if __name__ == "__main__":
    EncryptedQRApp().mainloop()