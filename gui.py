import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from main import gerar_chaves, criar_envelope, abrir_envelope


def escolher_arquivo(entry):
    caminho = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, caminho)


def executar_gerar_chaves():
    tamanho = tamanho_var.get()
    if tamanho not in ["1024", "2048"]:
        messagebox.showerror(
            "Erro", "Tamanho da chave inválido (1024 ou 2048)")
        return
    gerar_chaves(int(tamanho))
    messagebox.showinfo("Sucesso", "Chaves geradas com sucesso!")


def executar_criar_envelope():
    try:
        if aes_tam_var.get() not in ["16", "24", "32"]:
            messagebox.showerror(
                "Erro", "Tamanho da chave AES inválido. Use 16, 24 ou 32 bytes.")
            return

        criar_envelope(
            entrada=entrada_msg.get(),
            chave_publica_path=entrada_pub.get(),
            tamanho_aes=int(aes_tam_var.get()),
            modo_aes=modo_aes_var.get(),
            saida_base64=(saida_var.get() == "Base64"),
            saida_msg_path=saida_msg_entry.get(),
            saida_chave_path=saida_chave_entry.get()
        )
        messagebox.showinfo("Sucesso", "Envelope criado com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", str(e))


def executar_abrir_envelope():
    try:
        abrir_envelope(
            chave_privada_path=entrada_priv.get(),
            modo_aes=modo_aes2_var.get(),
            entrada_base64=(entrada_format_var.get() == "Base64")
        )
        messagebox.showinfo("Sucesso", "Envelope aberto com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", str(e))


# Configuração principal da janela
root = tk.Tk()
root.title("Envelope Digital - Segurança em Sistemas")
root.geometry("500x600")

# Canvas e Scrollbar para permitir rolagem
canvas = tk.Canvas(root)
scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
canvas.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand=True)

# Adicionar suporte ao scroll do mouse
def on_mouse_wheel(event):
    canvas.yview_scroll(-1 * (event.delta // 120), "units")

canvas.bind_all("<MouseWheel>", on_mouse_wheel)

# Frame interno para conter os widgets
scrollable_frame = ttk.Frame(canvas)

# Criar o window e guardar o ID para usar depois
frame_id = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

# Ajustar scrollregion dinamicamente
def on_configure(event):
    canvas.configure(scrollregion=canvas.bbox("all"))

scrollable_frame.bind("<Configure>", on_configure)

# Ajustar largura do frame interno quando a janela muda
def ajustar_largura(event):
    canvas.itemconfig(frame_id, width=event.width)

canvas.bind("<Configure>", ajustar_largura)

# --- Frames e widgets ---

# Frame 1: Gerar Chaves RSA
frame1 = ttk.LabelFrame(scrollable_frame, text="1. Gerar Chaves RSA")
frame1.pack(padx=10, pady=10, fill="x")

ttkk_lbl1 = ttk.Label(frame1, text="Escolha o tamanho da chave (em bits):")
ttkk_lbl1.pack(anchor="w", padx=5, pady=2)

tamanho_var = tk.StringVar(value="2048")
tamanho_menu = ttk.Combobox(frame1, textvariable=tamanho_var, values=["1024", "2048"], state="readonly")
tamanho_menu.pack(padx=5, pady=5, fill="x")

btn_gerar = ttk.Button(frame1, text="Gerar Chaves", command=executar_gerar_chaves)
btn_gerar.pack(pady=5)

# Frame 2: Criar Envelope Digital
frame2 = ttk.LabelFrame(scrollable_frame, text="2. Criar Envelope Digital")
frame2.pack(padx=10, pady=10, fill="x")

ttkk_lbl2 = ttk.Label(frame2, text="Mensagem de entrada (arquivo .txt ou binário):")
ttkk_lbl2.pack(anchor="w", padx=5, pady=2)
entrada_msg = ttk.Entry(frame2, width=50)
entrada_msg.pack(padx=5, fill="x")
ttk.Button(frame2, text="Selecionar Arquivo", command=lambda: escolher_arquivo(entrada_msg)).pack(pady=2)

ttkk_lbl3 = ttk.Label(frame2, text="Chave pública do destinatário (.pem):")
ttkk_lbl3.pack(anchor="w", padx=5, pady=2)
entrada_pub = ttk.Entry(frame2, width=50)
entrada_pub.pack(padx=5, fill="x")
ttk.Button(frame2, text="Selecionar Arquivo", command=lambda: escolher_arquivo(entrada_pub)).pack(pady=2)

ttkk_lbl4 = ttk.Label(frame2, text="Escolha o tamanho da chave AES (em bytes):")
ttkk_lbl4.pack(anchor="w", padx=5, pady=2)
aes_tam_var = tk.StringVar(value="16")
aes_menu = ttk.Combobox(frame2, textvariable=aes_tam_var, values=["16", "24", "32"], state="readonly")
aes_menu.pack(padx=5, pady=2, fill="x")

ttkk_lbl5 = ttk.Label(frame2, text="Modo de operação do AES:")
ttkk_lbl5.pack(anchor="w", padx=5, pady=2)
modo_aes_var = tk.StringVar(value="ECB")
modo_menu = ttk.Combobox(frame2, textvariable=modo_aes_var, values=["ECB", "CBC"], state="readonly")
modo_menu.pack(padx=5, pady=2, fill="x")

ttkk_lbl_saida_msg = ttk.Label(frame2, text="Nome do arquivo da mensagem cifrada (sem extensão):")
ttkk_lbl_saida_msg.pack(anchor="w", padx=5, pady=2)
saida_msg_entry = ttk.Entry(frame2)
saida_msg_entry.pack(padx=5, fill="x")

ttkk_lbl_saida_chave = ttk.Label(frame2, text="Nome do arquivo da chave cifrada (sem extensão):")
ttkk_lbl_saida_chave.pack(anchor="w", padx=5, pady=2)
saida_chave_entry = ttk.Entry(frame2)
saida_chave_entry.pack(padx=5, fill="x")

ttkk_lbl6 = ttk.Label(frame2, text="Formato de saída dos arquivos cifrados:")
ttkk_lbl6.pack(anchor="w", padx=5, pady=2)
saida_var = tk.StringVar(value="Base64")
saida_menu = ttk.Combobox(frame2, textvariable=saida_var, values=["Base64", "Hex"], state="readonly")
saida_menu.pack(padx=5, pady=2, fill="x")

ttk.Button(frame2, text="Criar Envelope", command=executar_criar_envelope).pack(pady=5)

# Frame 3: Abrir Envelope Digital
frame3 = ttk.LabelFrame(scrollable_frame, text="3. Abrir Envelope Digital")
frame3.pack(padx=10, pady=10, fill="x")

ttkk_lbl7 = ttk.Label(frame3, text="Chave privada do destinatário (.pem):")
ttkk_lbl7.pack(anchor="w", padx=5, pady=2)
entrada_priv = ttk.Entry(frame3, width=50)
entrada_priv.pack(padx=5, fill="x")
ttk.Button(frame3, text="Selecionar Arquivo", command=lambda: escolher_arquivo(entrada_priv)).pack(pady=2)

ttkk_lbl8 = ttk.Label(frame3, text="Modo de operação do AES usado na cifragem:")
ttkk_lbl8.pack(anchor="w", padx=5, pady=2)
modo_aes2_var = tk.StringVar(value="ECB")
modo2_menu = ttk.Combobox(frame3, textvariable=modo_aes2_var, values=["ECB", "CBC"], state="readonly")
modo2_menu.pack(padx=5, pady=2, fill="x")

ttkk_lbl9 = ttk.Label(frame3, text="Formato em que os arquivos estão codificados:")
ttkk_lbl9.pack(anchor="w", padx=5, pady=2)
entrada_format_var = tk.StringVar(value="Base64")
entrada_format_menu = ttk.Combobox(frame3, textvariable=entrada_format_var, values=["Base64", "Hex"], state="readonly")
entrada_format_menu.pack(padx=5, pady=2, fill="x")

ttk.Button(frame3, text="Abrir Envelope", command=executar_abrir_envelope).pack(pady=5)

# Iniciar o loop principal da interface
root.mainloop()