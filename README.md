# DCC075 - TVC1

Integrante: João Victor Pereira - 202176010

Sistema de criptografia híbrida (RSA-OAEP + AES-GCM) com assinatura (RSA-PSS) para arquivos em Node.js.

## Requisitos

- Node.js 16+ (ou superior)

## Estrutura do projeto

```
src/
  encrypt.js          # Criptografa e assina um arquivo de src/inputs
  decrypt.js          # Decifra e verifica um envelope de src/outputs
  inputs/             # Arquivos de entrada e chaves geradas (private_key.pem, public_key.pem)
  outputs/            # Envelopes gerados (.enc.json) e arquivos decifrados
  utils/encryption.js # Funções de hash, RSA, AES e utilitários
```

## Visão geral (como funciona)

- Criptografia híbrida:
    - Gera uma chave simétrica aleatória (AES-256) e cifra o conteúdo com AES-256-GCM.
    - "Encapsula" (wrap) a chave AES com RSA-OAEP (usando a chave pública).
- Assinatura:
    - Assina o plaintext com RSA-PSS (SHA-256) usando a chave privada.
- Envelope JSON:
    - Contém cabeçalho (metadados), assinatura e ciphertext base64, salvo em `src/outputs/<arquivo>.enc.json`.
- Chaves RSA (2048 bits):
    - Se não existirem, são geradas automaticamente em `src/inputs/` como `private_key.pem` e `public_key.pem`.

## Formato do envelope (.enc.json)

Campos principais gerados por `src/encrypt.js`:

- header
    - v: 2
    - enc: "hybrid: rsa-oaep(sha256) + aes-256-gcm"
    - sig: "rsa-pss(sha256)"
    - hashAlg: "sha256"
    - hash: SHA-256 em hex do conteúdo original (plaintext)
    - size: tamanho do plaintext (bytes)
    - iv: IV do AES-GCM (base64)
    - tag: Auth tag do AES-GCM (base64)
    - wrappedKey: chave AES cifrada com RSA-OAEP (base64)
- signature: assinatura RSA-PSS do plaintext (base64)
- ciphertext: conteúdo cifrado com AES-GCM (base64)

Exemplo (valores ilustrativos):

```
{
  "header": {
    "v": 2,
    "enc": "hybrid: rsa-oaep(sha256) + aes-256-gcm",
    "sig": "rsa-pss(sha256)",
    "hashAlg": "sha256",
    "hash": "f1a2...",
    "size": 1234,
    "iv": "base64...",
    "tag": "base64...",
    "wrappedKey": "base64..."
  },
  "signature": "base64...",
  "ciphertext": "base64..."
}
```

## Como executar

Você pode executar diretamente com Node ou usando scripts npm. Em ambos os casos, os caminhos são relativos à raiz do
projeto.

1) Criptografar e assinar

- Com Node:

```bash
# o arquivo de entrada deve existir em src/inputs/
node src/encrypt.js exemplo.txt
```

- Com npm (passando argumentos após --):

```bash
npm run encrypt -- exemplo.txt
```

Saída esperada: `src/outputs/exemplo.txt.enc.json`

2) Decifrar e verificar

- Com Node:

```bash
# o envelope deve existir em src/outputs/
node src/decrypt.js exemplo.enc.json
```

- Com npm:

```bash
npm run decrypt -- exemplo.enc.json
```

Saída esperada: `src/outputs/exemplo.txt` e logs como:

- Decrypted file written to: <CAMINHO>
- Signature verification: OK/FAILED
- Hash in header: <HASH_DO_HEADER>
- Hash computed: <HASH_CALCULADO>
- Hash verification: OK/FAILED

## Exemplo rápido

```bash
# 1) Criptografar (gera chaves RSA na primeira execução)
node src/encrypt.js exemplo.txt

# 2) Decifrar e verificar
node src/decrypt.js exemplo.enc.json

# Verifique src/outputs/ para o envelope e o arquivo decifrado
```

## Observações e limitações

- Tipos de arquivo: funciona com qualquer conteúdo binário/texto; a extensão `.txt` é apenas convenção de saída.
- Integridade e autenticidade:
    - A assinatura RSA-PSS é verificada sobre o plaintext.
    - O SHA-256 do plaintext é comparado ao `header.hash`.
- Se as chaves não existirem, `encrypt.js` gera automaticamente `private_key.pem` e `public_key.pem` em `src/inputs/`.
- Falhas na chave errada, envelope adulterado ou parâmetros inválidos resultarão em erro de decifragem/validação.
- IA utilizada apenas para geração deste README.

## Solução de problemas

- "Input file not found": confirme que o arquivo está em `src/inputs/` e passe apenas o nome (ex.: `exemplo.txt`).
- "Encrypted file not found": confirme que o `.enc.json` está em `src/outputs/` e passe apenas o nome (ex.:
  `exemplo.txt.enc.json`).
- "Missing key pair": rode a criptografia ao menos uma vez para gerar as chaves em `src/inputs/`.
- Para usar npm scripts, lembre-se de passar argumentos após `--` (ex.: `npm run encrypt -- exemplo.txt`).
