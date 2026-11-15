# Falkon — Arquitetura e Plano de Desenvolvimento (RRPM)

> **Sucessor em Rust do legado *Locust* (CripChat Python).**  
> Chat P2P 100% em terminal (CLI/TUI) com topologia Criador-como-Host, votação dupla de admissão, retenção efêmera configurável, Noise Protocol e abstração TCP pronta para `.onion`.

---

## Índice (Anchors)

* [1. R — Recursos (Stack e Estrutura)](#recursos)
* [2. R — Requisitos](#requisitos)
  * [2.1 Requisitos Funcionais (RF)](#requisitos-funcionais)
  * [2.2 Requisitos de Segurança e Não-Funcionais (RNF)](#requisitos-de-seguranca)
  * [2.3 Rede Local/NAT Hoje vs. `.onion` Futuro](#nat-e-onion)
* [3. P — Pontos de Desenvolvimento](#pontos)
  * [Ponto 1 — Workspace, Protocolo Base, Sanitização e Abstração Transport](#ponto-1)
  * [Ponto 2 — Criptografia Noise (`XXpsk3`), Argon2id e Identidade/Fingerprint](#ponto-2)
  * [Ponto 3 — Motor Host-Star P2P (Votação Dupla + Ciclo de Limpeza TTL)](#ponto-3)
  * [Ponto 4 — Hardening Anti-DoS, Rate Limit e Segurança de Processo](#ponto-4)
  * [Ponto 5 — Interface TUI Completa (`ratatui` em AlternateScreen)](#ponto-5)
  * [Ponto 6 — Auditoria, Fuzzing e Revisão de Segurança](#ponto-6)
  * [Ponto 7 — Canal Anônimo `.onion` v3 (Tor / Arti)](#ponto-7)
* [4. M — Marcos Atuais e Política de Releases](#marcos)
  * [4.1 Convenção de Codinomes (PT/ES)](#convencao-nomes)
  * [4.2 Estado Atual](#estado-atual)
  * [4.3 Fluxo de Release via GitHub Web](#fluxo-release-web)

---

<a id="recursos"></a>
## 1. R — Recursos (Stack e Estrutura)

```text
falkon/
├── Cargo.toml                  # Workspace root (100% Rust, edition 2024)
├── architecture.md             # Este documento
└── crates/
    ├── falkon-core/            # Protocolo, sanitização anti-ANSI, Argon2id, Noise, Sala/Votação/TTL
    ├── falkon-net/             # Trait PeerTransport (TCP direto + preparo .onion), framing, Noise stream
    └── falkon-tui/             # Binário principal: CLI (clap) + TUI (ratatui em AlternateScreen)
```

| Camada | Crates / Tecnologia | Papel |
| :--- | :--- | :--- |
| **Core & Segurança** | `snow`, `argon2`, `sha2`, `subtle`, `zeroize`, `getrandom`, `postcard`, `serde` | Handshake `Noise_XXpsk3`, derivação de PSK, framing, limpeza de RAM |
| **Rede & Transporte** | `tokio` (`TcpStream` / `TcpListener`) | Streams TCP ordenados compatíveis com Tor |
| **Interface Terminal** | `ratatui`, `crossterm`, `clap` | UI TUI em `AlternateScreen` sem *scrollback* |
| **Rede Tor (Ponto 7)** | `arti-client` / Tor `.onion` v3 (planejado) | Travessia de NAT/CGNAT e ocultação de IP |

---

<a id="requisitos"></a>
## 2. R — Requisitos

<a id="requisitos-funcionais"></a>
### 2.1 Requisitos Funcionais (RF)

* **RF-01 — Topologia Criador-como-Host:** O criador inicia uma sala em modo Host definindo a frase-segredo (PSK) e a política de retenção de histórico (`Não limpar`, `5s`, `15s`, `60s`).
* **RF-02 — Votação Dupla de Admissão:** Ao receber um novo participante (já aprovado no handshake Noise + PSK), o Host dispara uma votação para os membros ativos com **duas decisões independentes**:
  1. `allow_entry`: Permitir ou recusar a entrada do candidato na sala.
  2. `share_history`: Permitir ou negar o envio do histórico ativo recente (se houver) ao novato.
* **RF-03 — Ciclo Automático de Limpeza:** O Host mantém as mensagens ativas apenas na RAM durante o período configurado (`5s`, `15s`, `60s`) ou enquanto a sala estiver ativa (`Não limpar`), zerando da RAM cada mensagem expirada.
* **RF-04 — Interface 100% CLI/TUI:** Aplicação totalmente operável via terminal (`ratatui`), sem navegador nem JavaScript.
* **RF-05 — Verificação de Identidade:** Exibição do *fingerprint* da chave pública de cada peer na interface para conferência manual contra MitM.

<a id="requisitos-de-seguranca"></a>
### 2.2 Requisitos de Segurança e Não-Funcionais (RNF)

* **RNF-01 — Zero Código Inseguro:** `#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used)]` e `#![deny(clippy::expect_used)]` em todo o workspace.
* **RNF-02 — Memória Protegida:** `Zeroize` / `ZeroizeOnDrop` em chaves, PSKs, mensagens armazenadas e payloads decifrados.
* **RNF-03 — Segurança de Terminal:** Execução exclusiva em `AlternateScreen` (nenhuma mensagem vaza para o *scrollback* ao sair) e sanitização estrita anti-ANSI/controle em todo texto recebido pela rede.
* **RNF-04 — Transporte Orientado a Stream TCP:** Proibido depender de UDP/QUIC no núcleo de rede, garantindo portabilidade direta para túneis Tor `.onion`.
* **RNF-05 — Proteção de Lobby & Anti-DoS:** Framing com teto rígido (`65.535` bytes), limite de candidatos em espera, timeout em handshakes e votações, e canais limitados por peer.

<a id="nat-e-onion"></a>
### 2.3 Rede Local/NAT Hoje vs. `.onion` Futuro

* **Fase Atual (P2P TCP Direto — Testes em `127.0.0.1` / LAN):**
  * Conexões diretas via `DirectTcpTransport` funcionam imediatamente na mesma máquina (`127.0.0.1`), na mesma rede local (LAN) ou sobre VPNs privadas (WireGuard/Tailscale).
  * **Limitação conhecida em Internet aberta:** Redes residenciais e móveis utilizam **NAT / CGNAT**, impedindo que o Host receba conexões externas sem redirecionamento manual de porta no roteador (*Port Forwarding*), além de expor os IPs reais entre os peers.
* **Fase Futura ([Ponto 7](#ponto-7) — Canal `.onion`):**
  * A implementação do `OnionTransport` sobre a mesma `trait PeerTransport` (via `arti` em Rust puro ou daemon Tor) elimina a necessidade de abrir portas no roteador, atravessa qualquer NAT/CGNAT automaticamente e oculta o endereço IP real de todos os participantes.

---

<a id="pontos"></a>
## 3. P — Pontos de Desenvolvimento

<a id="ponto-1"></a>
### Ponto 1 — Workspace, Protocolo Base, Sanitização e Abstração Transport
* **Anchor:** `#ponto-1` | **Status:** **Implementado (Base inicial)**
* Estrutura Cargo (`falkon-core`, `falkon-net`, `falkon-tui`), lints `#![forbid(unsafe_code)]`, protocolo `WireMessage` com votação dupla e retenção TTL, sanitizador anti-ANSI, `PeerTransport` trait + `DirectTcpTransport` + módulo stub `.onion`.

<a id="ponto-2"></a>
### Ponto 2 — Criptografia Noise (`XXpsk3`), Argon2id e Identidade/Fingerprint
* **Anchor:** `#ponto-2` | **Status:** **Implementado (Núcleo + Handshake Async)**
* Derivação de PSK via Argon2id, geração de identidade X25519 + *fingerprint*, canal `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` com `padding` alinhado e testes de handshake em loopback TCP.

<a id="ponto-3"></a>
### Ponto 3 — Motor Host-Star P2P (Votação Dupla + Ciclo de Limpeza TTL)
* **Anchor:** `#ponto-3` | **Status:** **Núcleo pronto em `falkon-core`; falta integrar ao loop multi-peer em `falkon-net`**
* Orquestração assíncrona no Host gerenciando múltiplos peers conectados, fila de votação ao vivo, temporizador assíncrono (`5s`/`15s`/`60s`/`Never`) e relay cifrado para a sala.

<a id="ponto-4"></a>
### Ponto 4 — Hardening Anti-DoS, Rate Limit e Segurança de Processo
* **Anchor:** `#ponto-4` *(Segurança — Codinome Masculino)*
* Limite de conexões simultâneas, *rate limiting* por peer, timeout de sala de espera, proteção anti-replay e desativação de *core dumps* do processo (`rlimit`).

<a id="ponto-5"></a>
### Ponto 5 — Interface TUI Completa (`ratatui` em AlternateScreen)
* **Anchor:** `#ponto-5`
* TUI completa com painel de chat, modal/barra interativa de votação dupla (`[S/N]` Entrada + `[S/N]` Histórico), painel de peers/fingerprints, indicador de limpeza TTL e comandos (`/nick`, `/wipe`, `/quit`).

<a id="ponto-6"></a>
### Ponto 6 — Auditoria, Fuzzing e Revisão de Segurança
* **Anchor:** `#ponto-6` *(Segurança — Codinome Masculino)*
* `cargo-fuzz` no parser e sanitizador, `cargo-audit`, `cargo-deny`, revisão de zeragem de memória e remoção definitiva dos arquivos Python legados (*Locust*).

<a id="ponto-7"></a>
### Ponto 7 — Canal Anônimo `.onion` v3 (Tor / Arti)
* **Anchor:** `#ponto-7`
* Implementação concreta de `OnionTransport` com geração de endereço `.onion` v3 pelo Host e conexão de saída pelos peers sem exposição de IP nem abertura de portas no roteador.

---

<a id="marcos"></a>
## 4. M — Marcos Atuais e Política de Releases

<a id="convencao-nomes"></a>
### 4.1 Convenção de Codinomes (PT/ES)
* **Major / Marcos de Implementação:** Nomes **femininos** em português ou espanhol *(ex.: Clara, Sofía, Helena, Valentina)*.
* **Major / Marcos de Segurança:** Nomes **masculinos** em português ou espanhol *(ex.: Diego, Mateus, Rafael, Santiago)*.

<a id="estado-atual"></a>
### 4.2 Estado Atual

| Marco | Pontos | Tag Sugerida | Tipo / Codinome | Status |
| :--- | :--- | :--- | :--- | :--- |
| **M0 — Auditoria *Locust* (Python)** | Análise do legado | `v0.0.0-locust` | Segurança *(Base)* | **Concluído** |
| **M1 — Base, Cripto & Abstração TCP** | [Ponto 1](#ponto-1) + [Ponto 2](#ponto-2) | `v0.1.0` | Implementação — **"Clara"** | **Concluído** |
| **M2 — Motor Host & Votação P2P** | [Ponto 3](#ponto-3) | `v0.2.0` | Implementação — **"Sofía"** | **Concluído** |
| **M3 — Blindagem & Anti-DoS** | [Ponto 4](#ponto-4) | `v0.3.0` | Segurança — **"Diego"** | Pendente |
| **M4 — Interface TUI (`ratatui`)** | [Ponto 5](#ponto-5) | `v0.4.0` | Implementação — **"Helena"** | Pendente |
| **M5 — Auditoria & Fuzzing (1.0)** | [Ponto 6](#ponto-6) | `v1.0.0` | Segurança — **"Mateus"** | Pendente |
| **M6 — Rede `.onion` Nativa** | [Ponto 7](#ponto-7) | `v2.0.0` | Implementação — **"Valentina"** | Pendente |

<a id="fluxo-release-web"></a>
### 4.3 Fluxo de Release via GitHub Web

1. Rodar localmente antes do commit:
   * `cargo fmt --check`
   * `cargo clippy --all-targets -- -D warnings`
   * `cargo test --workspace`
2. Atualizar o status na tabela acima e enviar (`git push`).
3. No navegador: **GitHub → Releases → Draft a new release** → criar tag (ex.: `v0.1.0`), título `v0.1.0 — "Clara"`, referenciar o anchor (`#ponto-1`, `#ponto-2`) e publicar.
