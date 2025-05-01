import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

def gerar_chaves(tamanho=2048):
    chave = RSA.generate(tamanho)
    with open("chave_privada.pem", "wb") as f:
        f.write(chave.export_key())
    with open("chave_publica.pem", "wb") as f:
        f.write(chave.publickey().export_key())
    print("Chaves RSA geradas com sucesso!")

def criar_envelope(entrada, chave_publica_path, tamanho_aes, modo_aes, saida_base64,
                   saida_msg_path="mensagem_cifrada", saida_chave_path="chave_cifrada", chave_aes_fixa=None):
    if not os.path.exists(entrada):
        raise FileNotFoundError(f"Arquivo de entrada '{entrada}' não encontrado.")
    if not os.path.exists(chave_publica_path):
        raise FileNotFoundError(f"Arquivo de chave pública '{chave_publica_path}' não encontrado.")

    ext = ".b64" if saida_base64 else ".hex"

    with open(entrada, "rb") as f:
        dados = f.read()

    chave_aes = chave_aes_fixa if chave_aes_fixa else get_random_bytes(tamanho_aes)
    print(f'Chave AES: {chave_aes}')
    chave_aes_encoded = base64.b64encode(chave_aes)
    iv = get_random_bytes(16) if modo_aes == "CBC" else None
    cipher_aes = AES.new(chave_aes, AES.MODE_CBC, iv) if modo_aes == "CBC" else AES.new(chave_aes, AES.MODE_ECB)

    padding = 16 - len(dados) % 16
    dados += bytes([padding]) * padding
    msg_cifrada = cipher_aes.encrypt(dados)

    with open(chave_publica_path, "rb") as f:
        pub_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(pub_key)
    chave_cifrada = cipher_rsa.encrypt(chave_aes_encoded)

    if saida_base64:
        msg_cifrada_str = base64.b64encode(msg_cifrada).decode()
        chave_cifrada_str = base64.b64encode(chave_cifrada).decode()
        iv_saida = base64.b64encode(iv).decode() if iv else None
    else:
        msg_cifrada_str = msg_cifrada.hex()
        chave_cifrada_str = chave_cifrada.hex()
        iv_saida = iv.hex() if iv else None

    with open(saida_msg_path + ext, "w") as f:
        f.write(msg_cifrada_str)
    with open(saida_chave_path + ext, "w") as f:
        f.write(chave_cifrada_str)
    if iv_saida:
        with open("iv" + ext, "w") as f:
            f.write(iv_saida)

    print("Envelope criado com sucesso!")

def abrir_envelope(chave_privada_path, modo_aes, entrada_base64):
    if not os.path.exists("chave_cifrada.txt") or not os.path.exists("mensagem_cifrada.txt"):
        raise FileNotFoundError("Arquivos de entrada não encontrados.")

    with open(chave_privada_path, "rb") as f:
        priv_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(priv_key)

    with open("chave_cifrada.txt", "r") as f:
        chave_cifrada_str = f.read().strip()
        chave_cifrada = base64.b64decode(chave_cifrada_str) if entrada_base64 else bytes.fromhex(chave_cifrada_str)

    chave_aes_encoded = cipher_rsa.decrypt(chave_cifrada, None)
    chave_aes = base64.b64decode(chave_aes_encoded)

    with open("mensagem_cifrada.txt", "r") as f:
        msg_cifrada_str = f.read().strip()
        msg_cifrada = base64.b64decode(msg_cifrada_str) if entrada_base64 else bytes.fromhex(msg_cifrada_str)

    iv = None
    if modo_aes == "CBC":
        with open("iv.txt", "r") as f:
            iv_str = f.read()
            iv = base64.b64decode(iv_str) if entrada_base64 else bytes.fromhex(iv_str)

    cipher_aes = AES.new(chave_aes, AES.MODE_CBC, iv) if modo_aes == "CBC" else AES.new(chave_aes, AES.MODE_ECB)
    dados_decifrados = cipher_aes.decrypt(msg_cifrada)

    padding = dados_decifrados[-1]
    dados_decifrados = dados_decifrados[:-padding]

    with open("mensagem_decifrada.txt", "wb") as f:
        f.write(dados_decifrados)

    print("Envelope aberto com sucesso!")
    print("Arquivo restaurado: mensagem_decifrada.txt")

def menu():
    while True:
        print("\n==== MENU ENVELOPE DIGITAL ====")
        print("1 - Gerar par de chaves RSA")
        print("2 - Criar envelope")
        print("3 - Abrir envelope")
        print("0 - Sair")
        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            tamanho = int(input("Tamanho da chave (1024 ou 2048): "))
            gerar_chaves(tamanho)
        elif opcao == "2":
            entrada = input("Arquivo de entrada (ex: msg.txt): ")
            chave_pub = input("Chave pública (.pem): ")
            tam_aes = int(input("Tamanho AES (16, 24 ou 32): "))
            modo = input("Modo AES (ECB ou CBC): ").upper()
            base64_saida = input("Saída Base64? (s/n): ").lower() == 's'
            criar_envelope(entrada, chave_pub, tam_aes, modo, base64_saida)
        elif opcao == "3":
            chave_priv = input("Chave privada (.pem): ")
            modo = input("Modo AES (ECB ou CBC): ").upper()
            entrada_base64 = input("Entrada em Base64? (s/n): ").lower() == 's'
            abrir_envelope(chave_priv, modo, entrada_base64)
        elif opcao == "0":
            print("Saindo...")
            break
        else:
            print("Opção inválida!")

if __name__ == "__main__":
    menu()
