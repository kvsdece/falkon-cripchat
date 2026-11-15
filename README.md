<!-- Caminho: README.md -->

# Falkon

Mensageiro efêmero P2P 100% em terminal (CLI/TUI) escrito em Rust — sucessor do protótipo *Locust* (CripChat).

* **Zero histórico em disco:** tudo roda em memória RAM com `ZeroizeOnDrop` e `AlternateScreen` (nada vaza para o *scrollback* do terminal).
* **Criptografia P2P:** `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` + derivação `Argon2id` (mínimo 12 caracteres) + *padding* alinhado.
* **Votação Dupla de Admissão:** membros ativos votam individualmente se o novato pode **entrar** e se pode **receber o histórico ativo**.
* **Ciclo Automático de Limpeza:** o Host define se mensagens somem da RAM e da tela em `5s`, `15s`, `60s` ou `Não limpar` enquanto a sala durar.

---

## Como Executar

### Opção A — Modo Interativo (Mais fácil)
Basta rodar o executável sem nenhum argumento (ou via Cargo) e seguir o menu passo a passo:

```bash
./falkon
# ou compilando localmente:
cargo run --release -p falkon-tui
```

### Opção B — Direto por Flags (CLI)

#### 1. Testando no mesmo computador (2 terminais)
**Terminal 1 (Criador / Host):**
```bash
falkon --nick Clara --listen 127.0.0.1:7777 --retention 15s
```
**Terminal 2 (Peer):**
```bash
falkon --nick Mateus --connect 127.0.0.1:7777
```

#### 2. Entre computadores diferentes na mesma rede Wi-Fi / LAN / VPN
**Host (escutando em todas as interfaces):**
```bash
falkon --nick Clara --listen 0.0.0.0:7777 --retention 60s
```
**Peer (apontando para o IP local/VPN do Host):**
```bash
falkon --nick Mateus --connect 192.168.1.45:7777
```

> **Nota sobre Internet aberta:** Conexões TCP diretas exigem porta acessível caso o Host esteja atrás de NAT/CGNAT do provedor e expõem IPs entre participantes. O transporte anônimo `.onion` (Tor) está planejado no Marco **M6 ("Valentina")** para resolver ambos automaticamente.

#### Ver ajuda completa de flags
```bash
falkon --help
```

---

## Controles e Comandos na Sala

| Atalho / Comando | Ação |
| :--- | :--- |
| **`F1`** | Votar: **Aceitar entrada + enviar histórico ativo** |
| **`F2`** | Votar: **Aceitar entrada SEM histórico anterior** |
| **`F3`** | Votar: **Recusar entrada** *(qualquer recusa barra o candidato)* |
| **`/nick <nome>`** | Troca seu apelido dentro do canal cifrado |
| **`/peers`** | Lista participantes conectados e seus *fingerprints* (128 bits) |
| **`/fingerprint`** | Exibe sua identidade completa (**128b** e **SHA-256 256b**) |
| **`/clear`** | Limpa e zeroiza a tela local sem desconectar |
| **`/wipe`** | Zeroiza todo histórico/memória e encerra imediatamente |
| **`/help`** | Mostra ajuda rápida dentro da sala |
| **`/quit` ou `ESC`** | Sai com limpeza de memória e restaura o terminal |
| **`Setas / PgUp / PgDn`** | Edita texto (`Esq/Dir/Home/End/Del`) ou rola o histórico do chat (`Up/Down/PgUp/PgDn`) |

---

## Verificar Integridade do Binário (Releases)

Ao baixar `falkon-linux-x86_64` e `falkon-linux-x86_64.sha256` na aba **Releases**:

```bash
sha256sum -c falkon-linux-x86_64.sha256
chmod +x falkon-linux-x86_64
./falkon-linux-x86_64
```

## Desenvolvimento e Testes

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

Documentação arquitetural e roadmap (RRPM): [`architecture.md`](./architecture.md).