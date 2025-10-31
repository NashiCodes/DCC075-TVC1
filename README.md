# DCC075 - TVC1

Scripts para assinar (RSA-PSS/sha256) e criptografar arquivos (híbrido RSA-OAEP + AES-256-GCM), e para decifrar e
verificar assinatura e hash.

## Requisitos

- Node.js 16+ (ou superior)

## Como funciona (visão geral)

- encrypt.js
    - Gera par de chaves RSA (2048) em `src/inputs/` caso não exista: `private_key.pem`, `public_key.pem`.
    - Lê o arquivo em `src/inputs/<arquivo>`.
    - Calcula SHA-256 do conteúdo e assina o conteúdo com RSA-PSS (chave privada).
    - Gera uma chave AES aleatória (32 bytes) e cifra o conteúdo com AES-256-GCM.
    - Encripta ("wrap") a chave AES com RSA-OAEP (chave pública).
    - Salva um envelope JSON em `src/outputs/<arquivo>.enc.json` contendo: cabeçalho (hash, iv, tag, wrappedKey, etc.),
      assinatura e ciphertext.
- decrypt.js
    - Lê o envelope JSON de `src/outputs/`.
    - Desencripta a chave AES com a chave privada (RSA-OAEP) e decifra o conteúdo (AES-GCM).
    - Verifica a assinatura (RSA-PSS) com a chave pública e compara o SHA-256 do plaintext com o `header.hash`.
    - Salva o plaintext em `src/outputs/<arquivo>` (mesmo basename sem `.enc.json`).

## Uso

1) Criptografar e assinar

```bash
# arquivo deve existir em src/inputs/
node src/encrypt.js exemplo.txt
```

Saída: `src/outputs/exemplo.txt.enc.json`

2) Decifrar e verificar

```bash
# envelope deve existir em src/outputs/
node src/decrypt.js exemplo.enc.json
```

Saída: `src/outputs/exemplo.txt` e logs de verificação:

- Decrypted file written to: <PATH>
- Signature verification: OK/FAILED
- Hash in header: <HASH_VALUE>
- Hash computed: <HASH_VALUE>
- Hash verification: OK/FAILED

## Observações

- O cabeçalho guarda `hash` (SHA-256 do conteúdo original), `iv`, `tag`, e `wrappedKey` (chave AES cifrada com
  RSA-OAEP), além de metadados.
- A assinatura é feita sobre o plaintext, com RSA-PSS e SHA-256.
- Se as chaves não existirem, `encrypt.js` irá gerar automaticamente em `src/inputs/`.
- Se qualquer parte estiver incorreta (chave errada, envelope adulterado), a decifragem ou as verificações falharão.

