#!/usr/bin/env python3
"""
Aplicativo GUI para Anti-Ransomware.
Inicia o anti_ransomware.py em segundo plano como executável.
Requer: Tkinter e psutil (empacotados via PyInstaller).
"""

import tkinter as tk
from tkinter import messagebox
import subprocess
import sys
import os

def run_antiransomware():
    """
    Executa o anti_ransomware.py em segundo plano.
    Usa o caminho relativo ao executável empacotado.
    """
    # Caminho relativo ao anti_ransomware.py dentro do pacote
    script_path = os.path.join(os.path.dirname(sys.executable), "/home/kali/Challenge/anti-ransomware.py")  # Correção: remover caminho absoluto
    if not os.path.exists(script_path):
        messagebox.showerror("Erro", f"Arquivo anti-ransomware.py não encontrado no pacote.\nEntre em contato com o desenvolvedor.")
        return

    try:
        if sys.platform.startswith('win'):
            subprocess.Popen([sys.executable, script_path], creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            subprocess.Popen([sys.executable, script_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        messagebox.showinfo("Sucesso", "Anti-Ransomware iniciado em segundo plano!\nMonitore logs em anti_ransom_kills.log ou console para atualizações.")
        root.quit()  # Fecha a janela após iniciar
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao iniciar o Anti-Ransomware: {e}")

# Configuração da GUI
root = tk.Tk()
root.title("Anti-Ransomware Launcher")
root.geometry("400x200")
root.resizable(False, False)

# Label de crédito
credit_label = tk.Label(root, text="Feito por: Criptogr4f4d0s", font=("Arial", 8), fg="gray")
credit_label.pack(anchor="nw", padx=10, pady=5)

# Label principal
main_label = tk.Label(root, text="Proteja seus arquivos contra ransomware!", font=("Arial", 14), pady=20)
main_label.pack(expand=True)

# Botão principal
button = tk.Button(root, text="Clique para obter seu Anti-Ransomware", 
                   command=run_antiransomware, font=("Arial", 10), bg="green", fg="white",
                   width=40, height=2)
button.pack(pady=10)

# Centralizar a janela
root.update_idletasks()
width = root.winfo_width()
height = root.winfo_height()
x = (root.winfo_screenwidth() // 2) - (width // 2)
y = (root.winfo_screenheight() // 2) - (height // 2)
root.geometry(f"{width}x{height}+{x}+{y}")

# Iniciar o loop da GUI
print(f"Diretório atual: {os.getcwd()}")  # Depuração
root.mainloop()