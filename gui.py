import tkinter as tk
import os
from tkinter import filedialog, messagebox, ttk
from main import gerar_chaves, criar_envelope, abrir_envelope


class EnvelopeDigitalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Envelope Digital - Segurança em Sistemas")
        self.root.geometry("500x700")

        # Variáveis globais
        self.tamanho_var = tk.StringVar(value="2048")
        self.aes_tam_var = tk.StringVar(value="16")
        self.modo_aes_var = tk.StringVar(value="ECB")
        self.saida_var = tk.StringVar(value="Base64")
        self.modo_aes2_var = tk.StringVar(value="ECB")
        self.entrada_format_var = tk.StringVar(value="Base64")

        # Frames
        self.frame_menu = self.criar_frame_menu()
        self.frame_gerar_chaves = self.criar_frame_gerar_chaves()
        self.frame_criar_envelope = self.criar_frame_criar_envelope()
        self.frame_abrir_envelope = self.criar_frame_abrir_envelope()

        self.mostrar_frame(self.frame_menu)

    def mostrar_frame(self, frame):
        for widget in self.root.winfo_children():
            widget.pack_forget()
        frame.pack(fill="both", expand=True)

    def criar_frame_menu(self):
        frame = ttk.Frame(self.root)
        ttk.Label(frame, text="Escolha uma opção:", font=("Arial", 16)).pack(pady=20)
        ttk.Button(frame, text="Criptografar", command=self.mostrar_opcoes_criptografia).pack(pady=10)
        ttk.Button(frame, text="Descriptografar", command=lambda: self.mostrar_frame(self.frame_abrir_envelope)).pack(pady=10)
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

        ttk.Label(frame, text="Mensagem de entrada (arquivo .txt ou binário):").pack(anchor="w", padx=5, pady=2)
        self.entrada_msg = ttk.Entry(frame, width=50)
        self.entrada_msg.pack(padx=5, fill="x")
        ttk.Button(frame, text="Selecionar Arquivo", command=lambda: self.escolher_arquivo(self.entrada_msg)).pack(pady=2)

        ttk.Label(frame, text="Chave pública do destinatário (.pem):").pack(anchor="w", padx=5, pady=2)
        self.entrada_pub = ttk.Entry(frame, width=50)
        self.entrada_pub.pack(padx=5, fill="x")
        ttk.Button(frame, text="Selecionar Arquivo", command=lambda: self.escolher_arquivo(self.entrada_pub)).pack(pady=2)

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
        self.saida_msg_decifrada = self.criar_input_arquivo(frame, "Nome para salvar a mensagem decifrada:", salvar=True)

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
        entry.delete(0, tk.END)
        entry.insert(0, caminho)

    def executar_gerar_chaves(self):
        try:
            tamanho = int(self.tamanho_var.get())
            nome_privada = self.nome_privada_entry.get().strip() + ".pem"
            nome_publica = self.nome_publica_entry.get().strip() + ".pem"
            gerar_chaves(nome_privada=nome_privada, nome_publica=nome_publica, tamanho=tamanho)
            messagebox.showinfo("Sucesso", f"Chaves geradas:\n{nome_privada}\n{nome_publica}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def executar_criar_envelope(self):
        try:
            if not self.entrada_msg.get():
                raise ValueError("Por favor, selecione ou crie um arquivo de mensagem de entrada.")
            if not self.entrada_pub.get():
                raise ValueError("Por favor, selecione o arquivo de chave pública.")
            if self.aes_tam_var.get() not in ["16", "24", "32"]:
                raise ValueError("Tamanho da chave AES inválido. Use 16, 24 ou 32 bytes.")
            if not self.saida_msg_entry.get():
                raise ValueError("Por favor, informe o nome do arquivo de saída para a mensagem cifrada.")
            if not self.saida_chave_entry.get():
                raise ValueError("Por favor, informe o nome do arquivo de saída para a chave cifrada.")

            if not os.path.exists(self.entrada_msg.get()):
                raise FileNotFoundError(f"Arquivo de mensagem '{self.entrada_msg.get()}' não encontrado.")
            if not os.path.exists(self.entrada_pub.get()):
                raise FileNotFoundError(f"Arquivo de chave pública '{self.entrada_pub.get()}' não encontrado.")

            with open(self.entrada_pub.get(), "r") as f:
                conteudo_chave = f.read()
                if "PRIVATE KEY" in conteudo_chave:
                    raise ValueError("O arquivo selecionado é uma chave privada. Por favor, selecione uma chave pública válida.")

            criar_envelope(
                entrada=self.entrada_msg.get(),
                chave_publica_path=self.entrada_pub.get(),
                tamanho_aes=int(self.aes_tam_var.get()),
                modo_aes=self.modo_aes_var.get(),
                saida_base64=(self.saida_var.get() == "Base64"),
                saida_msg_path=self.saida_msg_entry.get(),
                saida_chave_path=self.saida_chave_entry.get()
            )
            messagebox.showinfo("Sucesso", "Envelope criado com sucesso!")
            self.mostrar_frame(self.frame_menu)
        except ValueError as ve:
            messagebox.showerror("Erro de Validação", str(ve))
        except FileNotFoundError as fnfe:
            messagebox.showerror("Erro de Arquivo", str(fnfe))
        except Exception as e:
            messagebox.showerror("Erro", f"Ocorreu um erro inesperado: {str(e)}")

    def executar_abrir_envelope(self):
        try:
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
        except Exception as e:
            messagebox.showerror("Erro", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = EnvelopeDigitalApp(root)
    root.mainloop()
