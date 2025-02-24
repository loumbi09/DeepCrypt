import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
import shutil

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DeepCrypt")
        self.root.geometry("720x620")
        self.root.configure(bg='#24445C')
        
        # Style modernisé
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configuration des couleurs
        self.style.configure('TFrame', background='#24445C')
        self.style.configure('TLabel', background='#24445C', foreground='white', font=('Helvetica', 10))
        self.style.configure('TButton', font=('Helvetica', 10, 'bold'), borderwidth=1)
        self.style.map('TButton',
            background=[('active', '#4a4a4a'), ('pressed', '#3a3a3a')],
            foreground=[('active', 'white')]
        )
        self.style.configure('TCombobox', fieldbackground='#3a3a3a', foreground='white')
        self.style.configure('TEntry', fieldbackground='#3a3a3a', foreground='white')
        self.style.configure('TCheckbutton', background='#24445C', foreground='white')
        self.style.configure('Horizontal.TProgressbar', troughcolor='#3a3a3a', background='#00ff88')
        
        # Barre de titre personnalisée
        self.title_bar = tk.Frame(self.root, bg='#1a1a1a', height=40, relief='flat', highlightthickness=0)
        self.title_bar.pack(fill=tk.X)
        
        self.title_label = tk.Label(self.title_bar, text='DeepCrypt', bg='#1a1a1a', fg='white', 
                                  font=('Helvetica', 12, 'bold'))
        self.title_label.pack(side=tk.LEFT, padx=15)
        
        # Boutons de contrôle de la fenêtre
        control_frame = tk.Frame(self.title_bar, bg='#1a1a1a')
        control_frame.pack(side=tk.RIGHT, padx=5)
        
        self.minimize_btn = tk.Button(control_frame, text='─', command=self.root.iconify, 
                                    bg='#1a1a1a', fg='white', bd=0, font=('Arial', 14),
                                    activebackground='#3a3a3a')
        self.minimize_btn.pack(side=tk.LEFT, padx=5)
        
        self.close_btn = tk.Button(control_frame, text='×', command=self.root.destroy, 
                                 bg='#1a1a1a', fg='white', bd=0, font=('Arial', 16),
                                 activebackground='#ff4444')
        self.close_btn.pack(side=tk.RIGHT)
        
        # Contenu principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(pady=20, padx=30, fill=tk.BOTH, expand=True)
        
        # Section de configuration
        config_frame = ttk.LabelFrame(main_frame, text=" Paramètres de chiffrement ", padding=15)
        config_frame.pack(fill=tk.X, pady=10)
        
        # Algorithme
        ttk.Label(config_frame, text="Algorithme :").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.algo_var = tk.StringVar()
        self.algo_combobox = ttk.Combobox(config_frame, textvariable=self.algo_var, 
                                        values=['AES-256-GCM', 'ChaCha20-Poly1305'], width=20)
        self.algo_combobox.current(0)
        self.algo_combobox.grid(row=0, column=1, padx=10, pady=5, sticky=tk.EW)
        
        # Itérations PBKDF2
        ttk.Label(config_frame, text="Itérations PBKDF2 :").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.iter_var = tk.IntVar(value=100000)
        self.iter_combobox = ttk.Combobox(config_frame, textvariable=self.iter_var, 
                                        values=[100000, 500000, 1000000], width=20)
        self.iter_combobox.grid(row=1, column=1, padx=10, pady=5, sticky=tk.EW)
        
        # Section mot de passe
        pwd_frame = ttk.LabelFrame(main_frame, text=" Sécurité ", padding=15)
        pwd_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(pwd_frame, text="Mot de passe :").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.pwd_entry = ttk.Entry(pwd_frame, show="•", width=25)
        self.pwd_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.EW)
        
        ttk.Label(pwd_frame, text="Confirmation :").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.pwd_confirm_entry = ttk.Entry(pwd_frame, show="•", width=25)
        self.pwd_confirm_entry.grid(row=1, column=1, padx=10, pady=5, sticky=tk.EW)
        
        # Section fichiers
        file_frame = ttk.LabelFrame(main_frame, text=" Fichiers ", padding=15)
        file_frame.pack(fill=tk.X, pady=10)
        
        self.file_button = ttk.Button(file_frame, text="📁 Sélectionner un fichier/dossier", 
                                    command=self.select_path, style='Accent.TButton')
        self.file_button.pack(pady=5, fill=tk.X)
        
        self.selection_label = ttk.Label(file_frame, text="Aucune sélection", foreground='#888888')
        self.selection_label.pack(pady=5)
        
        # Options
        self.delete_var = tk.BooleanVar()
        self.delete_check = ttk.Checkbutton(file_frame, text="Supprimer le fichier original après traitement", 
                                          variable=self.delete_var)
        self.delete_check.pack(pady=5)
        
        # Barre de progression
        self.progress = ttk.Progressbar(main_frame, orient='horizontal', mode='indeterminate', 
                                      style='Horizontal.TProgressbar')
        self.progress.pack(fill=tk.X, pady=15)
        
        # Boutons d'action
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.encrypt_button = ttk.Button(btn_frame, text="🔒 Chiffrer", command=self.start_encryption, 
                                       style='Accent.TButton')
        self.encrypt_button.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        self.decrypt_button = ttk.Button(btn_frame, text="🔓 Déchiffrer", command=self.start_decryption,
                                       style='Accent.TButton')
        self.decrypt_button.pack(side=tk.RIGHT, padx=5, fill=tk.X, expand=True)
        
        # Style supplémentaire
        self.style.configure('Accent.TButton', background='#00cc77', foreground='black', 
                           font=('Helvetica', 11, 'bold'), borderwidth=0)
        self.style.map('Accent.TButton',
            background=[('active', '#00ee88'), ('pressed', '#00aa66')],
            foreground=[('active', 'black')]
        )
        
        # Status
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, foreground='#00ff88')
        self.status_label.pack(pady=5)
        
        self.selected_path = ''
        self.running = False
    def select_path(self):
        # Sélection d'un fichier ou répertoire via une boîte de dialogue
        path = filedialog.askopenfilename() or filedialog.askdirectory()
        if path:
            self.selected_path = path
            self.selection_label.config(text=f"Selection: {path}")

    def toggle_buttons(self, state):
        # Active/désactive les boutons pendant le traitement
        self.encrypt_button.config(state=state)
        self.decrypt_button.config(state=state)
        self.file_button.config(state=state)

    def derive_key(self, password, salt, iterations):
        # Dérivation de clé avec PBKDF2-HMAC-SHA512
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),  # Algorithme de hash
            length=32,  # Taille de clé 256 bits
            salt=salt,  # Sel aléatoire
            iterations=iterations,  # Nombre d'itérations
            backend=default_backend()
        )
        return kdf.derive(password.encode())  # Dérivation de la clé

    def process_file(self, func, input_path, output_path):
        # Traitement d'un fichier (chiffrement/déchiffrement)
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Génération d'aléas cryptographiques
            salt = os.urandom(16)  # Sel pour PBKDF2
            nonce = os.urandom(12)  # Nonce pour les modes GCM
            
            if func == 'encrypt':
                # Dérivation de la clé de chiffrement
                key = self.derive_key(self.pwd_entry.get(), salt, self.iter_var.get())
                
                # Sélection de l'algorithme
                if self.algo_var.get() == 'AES-256-GCM':
                    cipher = AESGCM(key).encrypt(nonce, data, None)  # Chiffrement AES
                else:
                    cipher = ChaCha20Poly1305(key).encrypt(nonce, data, None)  # Chiffrement ChaCha
                
                # Écriture du fichier de sortie
                with open(output_path, 'wb') as f:
                    f.write(salt + nonce + cipher)  # Format: salt(16) + nonce(12) + données
                
            elif func == 'decrypt':
                # Extraction du sel et nonce depuis le fichier
                with open(input_path, 'rb') as f:
                    salt = f.read(16)
                    nonce = f.read(12)
                    cipher = f.read()
                
                # Régénération de la clé
                key = self.derive_key(self.pwd_entry.get(), salt, self.iter_var.get())
                
                # Déchiffrement selon l'algorithme
                if self.algo_var.get() == 'AES-256-GCM':
                    plaintext = AESGCM(key).decrypt(nonce, cipher, None)
                else:
                    plaintext = ChaCha20Poly1305(key).decrypt(nonce, cipher, None)
                
                # Écriture du résultat
                with open(output_path, 'wb') as f:
                    f.write(plaintext)
            
            return True
        except Exception as e:
            # Gestion des erreurs dans le thread GUI
            self.root.after(0, messagebox.showerror, "Erreur", str(e))
            return False

    def process_directory(self, func, input_dir, output_dir):
        # Traitement récursif d'un répertoire
        try:
            # Calcul de la progression
            total = sum(len(files) for _, _, files in os.walk(input_dir))
            current = 0
            
            # Parcours de l'arborescence
            for root, dirs, files in os.walk(input_dir):
                # Création des répertoires de sortie
                rel_path = os.path.relpath(root, input_dir)
                out_path = os.path.join(output_dir, rel_path)
                os.makedirs(out_path, exist_ok=True)
                
                # Traitement des fichiers
                for file in files:
                    in_file = os.path.join(root, file)
                    out_file = os.path.join(out_path, file)
                    
                    if func == 'encrypt':
                        out_file += '.enc'  # Extension pour les fichiers chiffrés
                        if not self.process_file(func, in_file, out_file):
                            return False
                    elif func == 'decrypt' and file.endswith('.enc'):
                        out_file = out_file[:-4]  # Suppression de l'extension
                        if not self.process_file(func, in_file, out_file):
                            return False
                    
                    # Mise à jour de la progression
                    current += 1
                    self.root.after(0, self.progress.step, (current/total)*100)
            
            return True
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Erreur", str(e))
            return False

    def start_encryption(self):
        # Lancement du chiffrement dans un thread séparé
        if self.validate_input():
            self.toggle_buttons('disabled')
            self.progress.start()
            threading.Thread(target=self.encrypt).start()

    def start_decryption(self):
        # Lancement du déchiffrement dans un thread séparé
        if self.validate_input():
            self.toggle_buttons('disabled')
            self.progress.start()
            threading.Thread(target=self.decrypt).start()

    def encrypt(self):
        # Gestion principale du chiffrement
        try:
            if os.path.isfile(self.selected_path):
                # Cas d'un fichier unique
                output = self.selected_path + '.enc'
                if self.process_file('encrypt', self.selected_path, output):
                    self.delete_original()
                    self.root.after(0, self.status_var.set, f"Fichier chiffré: {output}")
            else:
                # Cas d'un répertoire
                output = self.selected_path + '_encrypted'
                if self.process_directory('encrypt', self.selected_path, output):
                    self.delete_original()
                    self.root.after(0, self.status_var.set, f"Dossier chiffré: {output}")
        finally:
            # Nettoyage final
            self.root.after(0, self.progress.stop)
            self.root.after(0, self.toggle_buttons, 'normal')

    def decrypt(self):
        # Gestion principale du déchiffrement
        try:
            # Vérification de l'extension pour les fichiers
            if os.path.isfile(self.selected_path) and self.selected_path.endswith('.enc'):
                output = self.selected_path[:-4]
                if self.process_file('decrypt', self.selected_path, output):
                    self.delete_original()
                    self.root.after(0, self.status_var.set, f"Fichier déchiffré: {output}")
            # Vérification du suffixe pour les répertoires
            elif os.path.isdir(self.selected_path) and self.selected_path.endswith('_encrypted'):
                output = self.selected_path[:-10] + '_decrypted'
                if self.process_directory('decrypt', self.selected_path, output):
                    self.delete_original()
                    self.root.after(0, self.status_var.set, f"Dossier déchiffré: {output}")
            else:
                self.root.after(0, messagebox.showerror, "Erreur", "Sélection invalide pour déchiffrement")
        finally:
            self.root.after(0, self.progress.stop)
            self.root.after(0, self.toggle_buttons, 'normal')

    def delete_original(self):
        # Suppression sécurisée de l'original si activé
        if self.delete_var.get():
            try:
                if os.path.isfile(self.selected_path):
                    os.remove(self.selected_path)
                else:
                    shutil.rmtree(self.selected_path)  # Suppression récursive
            except Exception as e:
                self.root.after(0, messagebox.showwarning, "Avertissement", f"Échec de la suppression: {e}")

    def validate_input(self):
        # Validation des entrées utilisateur
        if not self.selected_path:
            messagebox.showerror("Erreur", "Sélectionnez un fichier/dossier")
            return False
        if self.pwd_entry.get() != self.pwd_confirm_entry.get():
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas")
            return False
        if not self.pwd_entry.get():
            messagebox.showerror("Erreur", "Entrez un mot de passe")
            return False
        return True
    

if __name__ == '__main__':
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
