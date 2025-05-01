
# GUI para o projeto de Envelope Digital
import tkinter as tk
import os
from tkinter import filedialog, messagebox, ttk, scrolledtext
from main import gerar_chaves, criar_envelope, abrir_envelope
import subprocess
import platform


class EnvelopeDigitalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Envelope Digital - Segurança em Sistemas")
        self.root.geometry("600x750")

        # Variáveis globais
        self.tamanho_var = tk.StringVar(value="2048")
        self.aes_tam_var = tk.StringVar(value="16")
        self.modo_aes_var = tk.StringVar(value="ECB")
        self.saida_var = tk.StringVar(value="Base64")
        self.modo_aes2_var = tk.StringVar(value="ECB")
        self.entrada_format_var = tk.StringVar(value="Base64")

        # Painel de log
        self.log_text = scrolledtext.ScrolledText(self.root, height=6, state='disabled', bg="#f0f0f0")
        self.log_text.pack(side="bottom", fill="x")

        # Frames
        self.frame_menu = self.criar_frame_menu()
        self.frame_gerar_chaves = self.criar_frame_gerar_chaves()
        self.frame_criar_envelope = self.criar_frame_criar_envelope()
        self.frame_abrir_envelope = self.criar_frame_abrir_envelope()

        self.mostrar_frame(self.frame_menu)
        
    def abrir_log(self):
        log_path = "log.txt"
        if not os.path.exists(log_path):
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("")

        try:
            sistema = platform.system()
            if sistema == "Windows":
                os.startfile(log_path)
            elif sistema == "Darwin":  # macOS
                subprocess.call(["open", log_path])
            else:  # Linux
                subprocess.call(["xdg-open", log_path])
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível abrir o log: {e}")


    def log(self, msg):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

        # Salva no arquivo de log
        with open("log.txt", "a", encoding="utf-8") as f:
            f.write(msg + "\n")


    def mostrar_frame(self, frame):
        for widget in self.root.winfo_children():
            if widget not in [self.log_text]:
                widget.pack_forget()
        frame.pack(fill="both", expand=True)

    def criar_frame_menu(self):
        frame = ttk.Frame(self.root)
        ttk.Label(frame, text="Escolha uma opção:", font=("Arial", 16)).pack(pady=20)
        ttk.Button(frame, text="Criptografar", command=self.mostrar_opcoes_criptografia).pack(pady=10)
        ttk.Button(frame, text="Descriptografar", command=lambda: self.mostrar_frame(self.frame_abrir_envelope)).pack(pady=10)
        ttk.Button(frame, text="🔍 Ver log completo", command=self.abrir_log).pack(pady=10)
        return frame

    def mostrar_opcoes_criptografia(self):
        resposta = messagebox.askyesno("Gerar Chaves", "Você deseja gerar chaves RSA?")
        if resposta:
            self.mostrar_frame(self.frame_gerar_chaves)
        else:
            self.mostrar_frame(self.frame_criar_envelope)

    def criar_frame_gerar_chaves(self):
        frame = ttk.Frame(self.root)
        ttk.Label(frame, text="Gerar Chaves RSA", font=("Arial", 16)).pack(pady=20)
        ttk.Label(frame, text="Escolha o tamanho da chave (em bits):").pack(anchor="w", padx=5, pady=2)
        tamanho_menu = ttk.Combobox(frame, textvariable=self.tamanho_var, values=["1024", "2048"], state="readonly")
        tamanho_menu.pack(padx=5, pady=5, fill="x")

        ttk.Label(frame, text="Nome da chave privada (sem .pem):").pack(anchor="w", padx=5, pady=2)
        self.nome_privada_entry = ttk.Entry(frame)
        self.nome_privada_entry.insert(0, "chave_privada")
        self.nome_privada_entry.pack(fill="x", padx=5)

        ttk.Label(frame, text="Nome da chave pública (sem .pem):").pack(anchor="w", padx=5, pady=2)
        self.nome_publica_entry = ttk.Entry(frame)
        self.nome_publica_entry.insert(0, "chave_publica")
        self.nome_publica_entry.pack(fill="x", padx=5)

        ttk.Button(frame, text="Gerar Chaves", command=self.executar_gerar_chaves).pack(pady=10)
        ttk.Button(frame, text="Avançar para Criar Envelope", command=lambda: self.mostrar_frame(self.frame_criar_envelope)).pack(pady=10)
        ttk.Button(frame, text="Voltar", command=lambda: self.mostrar_frame(self.frame_menu)).pack(pady=10)
        return frame

    def criar_frame_criar_envelope(self):
        frame = ttk.Frame(self.root)
        ttk.Label(frame, text="Criar Envelope Digital", font=("Arial", 16)).pack(pady=20)

        self.entrada_msg = self.criar_input_arquivo(frame, "Mensagem de entrada (arquivo .txt ou binário):")
        self.entrada_pub = self.criar_input_arquivo(frame, "Chave pública do destinatário (.pem):")

        ttk.Label(frame, text="Escolha o tamanho da chave AES (em bytes):").pack(anchor="w", padx=5, pady=2)
        aes_menu = ttk.Combobox(frame, textvariable=self.aes_tam_var, values=["16", "24", "32"], state="readonly")
        aes_menu.pack(padx=5, pady=2, fill="x")

        ttk.Label(frame, text="Modo de operação do AES:").pack(anchor="w", padx=5, pady=2)
        modo_menu = ttk.Combobox(frame, textvariable=self.modo_aes_var, values=["ECB", "CBC"], state="readonly")
        modo_menu.pack(padx=5, pady=2, fill="x")

        ttk.Label(frame, text="Nome do arquivo da mensagem cifrada (sem extensão):").pack(anchor="w", padx=5, pady=2)
        self.saida_msg_entry = ttk.Entry(frame)
        self.saida_msg_entry.pack(padx=5, fill="x")

        ttk.Label(frame, text="Nome do arquivo da chave cifrada (sem extensão):").pack(anchor="w", padx=5, pady=2)
        self.saida_chave_entry = ttk.Entry(frame)
        self.saida_chave_entry.pack(padx=5, fill="x")

        ttk.Label(frame, text="Formato de saída dos arquivos cifrados:").pack(anchor="w", padx=5, pady=2)
        saida_menu = ttk.Combobox(frame, textvariable=self.saida_var, values=["Base64", "Hex"], state="readonly")
        saida_menu.pack(padx=5, pady=2, fill="x")

        ttk.Button(frame, text="Criar Envelope", command=self.executar_criar_envelope).pack(pady=10)
        ttk.Button(frame, text="Voltar", command=lambda: self.mostrar_frame(self.frame_menu)).pack(pady=10)
        return frame

    def criar_frame_abrir_envelope(self):
        frame = ttk.Frame(self.root)
        ttk.Label(frame, text="Abrir Envelope Digital", font=("Arial", 16)).pack(pady=10)

        self.entrada_priv = self.criar_input_arquivo(frame, "Chave privada do destinatário (.pem):")
        self.entrada_chave_cifrada = self.criar_input_arquivo(frame, "Arquivo da chave AES cifrada:")
        self.entrada_msg_cifrada = self.criar_input_arquivo(frame, "Arquivo da mensagem cifrada:")
        self.entrada_iv = self.criar_input_arquivo(frame, "Arquivo IV (apenas se CBC):")
        ttk.Label(frame, text="Nome para salvar a mensagem decifrada (com extensão):").pack(anchor="w", padx=5, pady=2)
        self.saida_msg_decifrada = ttk.Entry(frame, width=50)
        self.saida_msg_decifrada.pack(padx=5, fill="x")
        ttk.Label(frame, text="Modo de operação do AES usado na cifragem:").pack(anchor="w", padx=5, pady=2)
        modo2_menu = ttk.Combobox(frame, textvariable=self.modo_aes2_var, values=["ECB", "CBC"], state="readonly")
        modo2_menu.pack(padx=5, pady=2, fill="x")

        ttk.Label(frame, text="Formato em que os arquivos estão codificados:").pack(anchor="w", padx=5, pady=2)
        entrada_format_menu = ttk.Combobox(frame, textvariable=self.entrada_format_var, values=["Base64", "Hex"], state="readonly")
        entrada_format_menu.pack(padx=5, pady=2, fill="x")

        ttk.Button(frame, text="Abrir Envelope", command=self.executar_abrir_envelope).pack(pady=10)
        ttk.Button(frame, text="Voltar", command=lambda: self.mostrar_frame(self.frame_menu)).pack(pady=10)
        return frame

    def criar_input_arquivo(self, frame, texto, salvar=False):
        ttk.Label(frame, text=texto).pack(anchor="w", padx=5, pady=2)
        entry = ttk.Entry(frame, width=50)
        entry.pack(padx=5, fill="x")
        botao = ttk.Button(frame, text="Selecionar Arquivo", command=lambda: self.escolher_arquivo(entry, salvar))
        botao.pack(pady=2)
        return entry

    def escolher_arquivo(self, entry, salvar=False):
        caminho = filedialog.asksaveasfilename() if salvar else filedialog.askopenfilename()
        if caminho:
            entry.delete(0, tk.END)
            entry.insert(0, caminho)

    def executar_gerar_chaves(self):
        try:
            nome_privada = self.nome_privada_entry.get().strip()
            nome_publica = self.nome_publica_entry.get().strip()
            if not nome_privada or not nome_publica:
                raise ValueError("Nomes de arquivos de chave não podem estar vazios.")
            tamanho = int(self.tamanho_var.get())
            gerar_chaves(nome_privada + ".pem", nome_publica + ".pem", tamanho)
            messagebox.showinfo("Sucesso", "Chaves geradas com sucesso!")
            self.log(f"Chaves RSA geradas: {nome_privada}.pem, {nome_publica}.pem")
        except Exception as e:
            messagebox.showerror("Erro ao gerar chaves", str(e))
            self.log(f"Erro ao gerar chaves: {str(e)}")

    def executar_criar_envelope(self):
        try:
            campos = {
                "Mensagem de entrada": self.entrada_msg.get(),
                "Chave pública": self.entrada_pub.get(),
                "Mensagem cifrada (nome)": self.saida_msg_entry.get(),
                "Chave cifrada (nome)": self.saida_chave_entry.get(),
            }
            for campo, valor in campos.items():
                if not valor:
                    raise ValueError(f"O campo '{campo}' está vazio.")

            if not os.path.exists(campos["Mensagem de entrada"]):
                raise FileNotFoundError("Arquivo de mensagem não encontrado.")
            if not os.path.exists(campos["Chave pública"]):
                raise FileNotFoundError("Arquivo de chave pública não encontrado.")

            with open(campos["Chave pública"], "r") as f:
                if "PRIVATE KEY" in f.read():
                    raise ValueError("Chave pública inválida. Parece ser uma chave privada.")

            output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)

            criar_envelope(
                entrada=campos["Mensagem de entrada"],
                chave_publica_path=campos["Chave pública"],
                tamanho_aes=int(self.aes_tam_var.get()),
                modo_aes=self.modo_aes_var.get(),
                saida_base64=(self.saida_var.get() == "Base64"),
                saida_msg_path=os.path.join(output_dir, self.saida_msg_entry.get()),
                saida_chave_path=os.path.join(output_dir, self.saida_chave_entry.get())
            )
            messagebox.showinfo("Sucesso", "Envelope criado com sucesso!")
            self.log("Envelope digital criado com sucesso.")
            self.mostrar_frame(self.frame_menu)
        except Exception as e:
            messagebox.showerror("Erro ao criar envelope", str(e))
            self.log(f"Erro ao criar envelope: {str(e)}")

    def executar_abrir_envelope(self):
        try:
            campos = {
                "Chave privada": self.entrada_priv.get(),
                "Chave cifrada": self.entrada_chave_cifrada.get(),
                "Mensagem cifrada": self.entrada_msg_cifrada.get(),
                "Saída da mensagem": self.saida_msg_decifrada.get()
            }
            for campo, valor in campos.items():
                if not valor:
                    raise ValueError(f"O campo '{campo}' está vazio.")

            if self.modo_aes2_var.get() == "CBC" and not self.entrada_iv.get():
                raise ValueError("O campo 'Arquivo IV' é obrigatório no modo CBC.")

            abrir_envelope(
                chave_privada_path=self.entrada_priv.get(),
                modo_aes=self.modo_aes2_var.get(),
                entrada_base64=(self.entrada_format_var.get() == "Base64"),
                path_chave_cifrada=self.entrada_chave_cifrada.get(),
                path_msg_cifrada=self.entrada_msg_cifrada.get(),
                path_iv=self.entrada_iv.get(),
                path_saida=self.saida_msg_decifrada.get()
            )
            messagebox.showinfo("Sucesso", "Envelope aberto com sucesso!")
            self.log("Envelope digital aberto com sucesso.")
        except Exception as e:
            messagebox.showerror("Erro ao abrir envelope", str(e))
            self.log(f"Erro ao abrir envelope: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = EnvelopeDigitalApp(root)
    root.mainloop()
