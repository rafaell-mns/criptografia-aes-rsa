import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
import os
from math import ceil

from Crypto.PublicKey import RSA




def gerar_chaves(nome_privada, nome_publica, tamanho):
    output_dir = "output/chaves_RSA"
    os.makedirs(output_dir, exist_ok=True)

    chave = RSA.generate(tamanho)
    chave_privada = chave.export_key()
    chave_publica = chave.publickey().export_key()

    with open(os.path.join(output_dir, nome_privada), "wb") as f:
        f.write(chave_privada)
    with open(os.path.join(output_dir, nome_publica), "wb") as f:
        f.write(chave_publica)

    print(f"\nChaves RSA de {tamanho} bits geradas com sucesso!")
    print(f"Chave privada salva em: {os.path.join(output_dir, nome_privada)}")
    print(f"Chave pública salva em: {os.path.join(output_dir, nome_publica)}\n")


def criar_envelope(entrada, chave_publica_path, tamanho_aes, modo_aes, saida_base64,
                   saida_msg_path="mensagem_cifrada", saida_chave_path="chave_cifrada",):
    if not os.path.exists(entrada):
        raise FileNotFoundError(f"Arquivo de entrada '{entrada}' não encontrado.")
    if not os.path.exists(chave_publica_path):
        raise FileNotFoundError(f"Arquivo de chave pública '{chave_publica_path}' não encontrado.")

    ext = ".b64" if saida_base64 else ".hex"

    with open(entrada, "rb") as f:
        dados = f.read()

    chave_aes = get_random_bytes(tamanho_aes) 

  

    if len(chave_aes) not in (16, 24, 32):
        raise ValueError("Erro: Tamanho da chave AES inválido. Deve ser 16, 24 ou 32 bytes.")

    print(f'Chave AES: {chave_aes}')
    print(f"[DEBUG] Tamanho da chave AES: {len(chave_aes)} bytes")
    

    
    iv = get_random_bytes(16) if modo_aes == "CBC" else None
    cipher_aes = AES.new(chave_aes, AES.MODE_CBC, iv) if modo_aes == "CBC" else AES.new(chave_aes, AES.MODE_ECB)

    padding = AES.block_size - len(dados) % AES.block_size
    dados += bytes([padding]) * padding
    msg_cifrada = cipher_aes.encrypt(dados)

    with open(chave_publica_path, "rb") as f:
        pub_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(pub_key)

    
    chave_aes = base64.b64encode(chave_aes)  

    #chave_aes = chave_aes[:tamanho_aes]

    chave_cifrada = cipher_rsa.encrypt(chave_aes)

    if saida_base64:
        msg_cifrada_str = base64.b64encode(msg_cifrada).decode()
        chave_cifrada_str = base64.b64encode(chave_cifrada).decode()
        iv_saida = iv.hex() if iv else None
    else:
        msg_cifrada_str = msg_cifrada.hex()
        chave_cifrada_str = chave_cifrada.hex()
        iv_saida = iv.hex() if iv else None

    with open(saida_msg_path + ext, "w") as f:
        f.write(msg_cifrada_str)
    with open(saida_chave_path + ext, "w") as f:
        f.write(chave_cifrada_str)
    if iv_saida:
        with open("iv.hex", "w") as f:
            f.write(iv_saida)

    print("Envelope criado com sucesso!")

def abrir_envelope(chave_privada_path, modo_aes, entrada_base64,
                   path_chave_cifrada="chave_cifrada.txt",
                   path_msg_cifrada="mensagem_cifrada.txt",
                   path_iv="iv.hex",
                   cyberchef=False,
                   path_saida="mensagem_decifrada.txt"):

    # Verificação de arquivos obrigatórios
    if not all(map(os.path.exists, [chave_privada_path, path_chave_cifrada, path_msg_cifrada])):
        raise FileNotFoundError("Algum dos arquivos necessários não foi encontrado.")

    # Carrega chave privada
    with open(chave_privada_path, "rb") as f:
        chave_privada = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(chave_privada)

    # Lê e decodifica a chave cifrada
    with open(path_chave_cifrada, "r") as f:
        chave_cifrada_str = f.read().strip()
        chave_cifrada = base64.b64decode(chave_cifrada_str) if entrada_base64 else bytes.fromhex(chave_cifrada_str)

    print(f"[DEBUG] Tamanho da chave cifrada: {len(chave_cifrada)} bytes")

    # Decifra a chave AES
    sentinel = b"ERRO"
    chave_aes = cipher_rsa.decrypt(chave_cifrada, sentinel)
    if chave_aes == sentinel:
        raise ValueError("Erro ao decifrar a chave AES (RSA).")
    
    if not cyberchef:
        chave_aes = base64.b64decode(chave_aes) 

    print(f"[DEBUG] Tamanho da chave AES: {len(chave_aes)} bytes")
    print(f"[DEBUG] Chave AES decifrada: {chave_aes}")

    if len(chave_aes) not in (16, 24, 32):
        raise ValueError("Erro: Tamanho da chave AES inválido. Deve ser 16, 24 ou 32 bytes.\nVerifique em que lugar se iniciou o processo de criptografia (nesse programa ou no CyberChef)\nSe não foi no Cyberchef desmarque a caixa da primeira pergunta\nSe foi no Cyberchef marque a caixa da primeira pergunta")

    # Lê e decodifica a mensagem cifrada
    with open(path_msg_cifrada, "r") as f:
        msg_cifrada_str = f.read().strip()
        msg_cifrada = base64.b64decode(msg_cifrada_str) if entrada_base64 else bytes.fromhex(msg_cifrada_str)

    # Lê o IV se for modo CBC
    iv = None
    if modo_aes.upper() == "CBC":
        if not os.path.exists(path_iv):
            raise FileNotFoundError("IV necessário para modo CBC não encontrado.")
        with open(path_iv, "r") as f:
            iv_str = f.read().strip()
            iv = bytes.fromhex(iv_str)

    # Decifra a mensagem
    cipher_aes = AES.new(chave_aes, AES.MODE_CBC, iv) if modo_aes.upper() == "CBC" else AES.new(chave_aes, AES.MODE_ECB)
    dados_decifrados = cipher_aes.decrypt(msg_cifrada)

    # Remove padding
    padding = dados_decifrados[-1]
    if not (1 <= padding <= AES.block_size) or dados_decifrados[-padding:] != bytes([padding]) * padding:
        raise ValueError("Erro de padding: padding inválido ou incorreto. Verifique se o modo AES usado é o mesmo da cifra original.")
    dados_decifrados = dados_decifrados[:-padding]

    # Salva saída
    with open(path_saida, "wb") as f:
        f.write(dados_decifrados)

    print(f"[INFO] Envelope aberto com sucesso! Mensagem salva em '{path_saida}'")


