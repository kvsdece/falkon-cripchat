<!-- Caminho: architecture.md -->

# Falkon — Arquitetura e Plano de Desenvolvimento (RRPM)

> **Sucessor em Rust do legado *Locust* (CripChat Python).**  
> Chat P2P 100% em terminal (CLI/TUI) com topologia Criador-como-Host, votação dupla de admissão, retenção efêmera sincronizada na RAM e na UI, Noise Protocol e abstração TCP pronta para `.onion`.

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
  * [Ponto 5 — Interface TUI Polida (`ratatui` em AlternateScreen)](#ponto-5)
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
├── .github/workflows/
│   └── release.yml             # Build automatizado de binario Linux + SHA-256 por tag/release
└── crates/
    ├── falkon-core/            # Protocolo, sanitizacao anti-ANSI, Argon2id, Noise, Sala/Votacao/TTL, Replay/Bucket
    ├── falkon-net/             # Trait PeerTransport (TCP direto + preparo .onion), Host/Peer, RateLimiter
    └── falkon-tui/             # Binario `falkon`: CLI (clap) + TUI (ratatui em AlternateScreen)
```

| Camada | Crates / Tecnologia | Papel |
| :--- | :--- | :--- |
| **Core & Segurança** | `snow`, `argon2`, `sha2`, `subtle`, `zeroize`, `getrandom`, `postcard`, `serde` | Handshake `Noise_XXpsk3`, PSK >= 12 chars, Fingerprint 128/256b, ReplayGuard |
| **Rede & Transporte** | `tokio` (`TcpStream` / `TcpListener`) | Streams TCP ordenados compatíveis com Tor |
| **Interface Terminal** | `ratatui`, `crossterm`, `clap`, `rpassword`, `rlimit` | UI TUI em `AlternateScreen`, prompt oculto e `RLIMIT_CORE=0` |
| **Rede Tor (Ponto 7)** | `arti-client` / Tor `.onion` v3 (planejado) | Travessia de NAT/CGNAT e ocultação de IP |

---

<a id="requisitos"></a>
## 2. R — Requisitos

<a id="requisitos-funcionais"></a>
### 2.1 Requisitos Funcionais (RF)

* **RF-01 — Topologia Criador-como-Host:** O criador inicia a sala em modo Host definindo o segredo (>= 12 caracteres) e a política de retenção (`Não limpar`, `5s`, `15s`, `60s`).
* **RF-02 — Votação Dupla de Admissão:** Ao receber um novo participante autenticado no Noise + PSK, o Host dispara votação para os membros ativos com duas decisões independentes (`allow_entry` e `share_history`).
* **RF-03 — Ciclo Automático de Limpeza Sincronizado:** Quando configurada retenção (`5s`, `15s`, `60s`), as mensagens vencidas são expiradas e zeroizadas na RAM tanto no buffer do Host quanto na exibição de `AppState` (Host e Peers).
* **RF-04 — Interface 100% CLI/TUI:** Aplicação operável via terminal (`ratatui`), sem navegador nem JavaScript.
* **RF-05 — Verificação de Identidade:** Fingerprint de **128 bits** visível nos painéis + comando `/fingerprint` com hash **256 bits** completo para conferência manual contra MitM.

<a id="requisitos-de-seguranca"></a>
### 2.2 Requisitos de Segurança e Não-Funcionais (RNF)

* **RNF-01 — Zero Código Inseguro:** `#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used)]` e `#![deny(clippy::expect_used)]` em todo o workspace.
* **RNF-02 — Memória Protegida:** `Zeroize` / `ZeroizeOnDrop` em chaves, PSKs, mensagens armazenadas e fila da TUI + `RLIMIT_CORE = 0` em Unix.
* **RNF-03 — Handshake Seguro e Senha Forte:** `Noise_XXpsk3` + `Argon2id` com segredo mínimo de 12 caracteres sem repetição trivial.
* **RNF-04 — Segurança de Terminal:** Execução exclusiva em `AlternateScreen` e sanitização anti-ANSI/controle em todo texto remoto.
* **RNF-05 — Transporte Orientado a Stream TCP:** Sem dependência de UDP/QUIC para garantir compatibilidade futura com Tor `.onion`.
* **RNF-06 — Blindagem Anti-DoS e Anti-Replay:** Semáforo de handshakes, orçamento de 10s no pré-lobby, limite de 2 KB por frame no handshake, `ConnectionRateLimiter` por IP, `ReplayGuard`, `TokenBucket` e voto único.

<a id="nat-e-onion"></a>
### 2.3 Rede Local/NAT Hoje vs. `.onion` Futuro

* **Fase Atual (P2P TCP Direto — Testes locais / LAN / VPN):** Funciona imediatamente em `127.0.0.1`, rede local ou VPN privada; na internet aberta exige porta aberta no roteador caso atrás de NAT/CGNAT e expõe IPs entre peers.
* **Fase Futura ([Ponto 7](#ponto-7) — Canal `.onion`):** O `OnionTransport` sobre a mesma `trait PeerTransport` eliminará abertura de portas no roteador e ocultará os IPs reais.

---

<a id="pontos"></a>
## 3. P — Pontos de Desenvolvimento

<a id="ponto-1"></a>
### Ponto 1 — Workspace, Protocolo Base, Sanitização e Abstração Transport
* **Anchor:** `#ponto-1` | **Status:** **Concluído (`v0.1.0`)**

<a id="ponto-2"></a>
### Ponto 2 — Criptografia Noise (`XXpsk3`), Argon2id e Identidade/Fingerprint
* **Anchor:** `#ponto-2` | **Status:** **Concluído (`v0.1.0`, reforçado em `v0.3.1`)**

<a id="ponto-3"></a>
### Ponto 3 — Motor Host-Star P2P (Votação Dupla + Ciclo de Limpeza TTL)
* **Anchor:** `#ponto-3` | **Status:** **Concluído (`v0.2.0` / `v0.2.1`, limpeza de UI fechada em `v0.3.1`)**

<a id="ponto-4"></a>
### Ponto 4 — Hardening Anti-DoS, Rate Limit e Segurança de Processo
* **Anchor:** `#ponto-4` *(Segurança — Codinome "Diego")* | **Status:** **Concluído (`v0.3.0` / `v0.3.1`)**

<a id="ponto-5"></a>
### Ponto 5 — Interface TUI Polida (`ratatui` em AlternateScreen)
* **Anchor:** `#ponto-5` | **Status:** **Próximo**
* Cursor visível e edição com setas na caixa de entrada, rolagem manual (`PageUp`/`PageDown`/`End`), comando `/help`, `/peers`, indicadores de limpeza TTL e layout responsivo aprimorado.

<a id="ponto-6"></a>
### Ponto 6 — Auditoria, Fuzzing e Revisão de Segurança
* **Anchor:** `#ponto-6` *(Segurança — Codinome "Mateus")* | **Status:** Pendente
* `cargo-fuzz` no parser e sanitizador, `cargo-audit`, `cargo-deny` (`deny.toml`) e revisão geral de código antes da `v1.0.0`.

<a id="ponto-7"></a>
### Ponto 7 — Canal Anônimo `.onion` v3 (Tor / Arti)
* **Anchor:** `#ponto-7` | **Status:** Pendente
* Implementação de `OnionTransport` com geração de endereço `.onion` v3 pelo Host e conexão anônima pelos peers.

---

<a id="marcos"></a>
## 4. M — Marcos Atuais e Política de Releases

<a id="convencao-nomes"></a>
### 4.1 Convenção de Nomes das Releases
* **Atualizações principais de Implementação:** Nomes **femininos** em PT/ES *(ex.: Clara, Sofía, Helena, Valentina)*.
* **Atualizações principais de Segurança:** Nomes **masculinos** em PT/ES *(ex.: Diego, Mateus, Rafael, Santiago)*.
* **Subatualizações / Patches (`x.y.Z`):** Mantêm o codinome do marco atual.

<a id="estado-atual"></a>
### 4.2 Estado Atual

| Marco | Pontos | Tag Alvo | Tipo / Codinome | Status |
| :--- | :--- | :--- | :--- | :--- |
| **M0 — Legado *Locust* (Python)** | Auditoria inicial | `v0.0.0-locust` | Segurança *(Base)* | **Concluído** |
| **M1 — Base, Cripto & Abstração TCP** | [Ponto 1](#ponto-1) + [Ponto 2](#ponto-2) | `v0.1.0` | Implementação — **"Clara"** | **Concluído** |
| **M2 — Motor Host & Votação P2P** | [Ponto 3](#ponto-3) | `v0.2.0` / `v0.2.1` | Implementação — **"Sofía"** | **Concluído** |
| **M3 — Blindagem & Anti-DoS** | [Ponto 4](#ponto-4) | `v0.3.0` / `v0.3.1` | Segurança — **"Diego"** | **Concluído** |
| **M4 — Interface TUI (`ratatui`)** | [Ponto 5](#ponto-5) | `v0.4.0` | Implementação — **"Helena"** | **Próximo** |
| **M5 — Auditoria & Fuzzing (1.0)** | [Ponto 6](#ponto-6) | `v1.0.0` | Segurança — **"Mateus"** | Pendente |
| **M6 — Canal `.onion` Nativa** | [Ponto 7](#ponto-7) | `v2.0.0` | Implementação — **"Valentina"** | Pendente |

<a id="fluxo-release-web"></a>
### 4.3 Fluxo de Release via GitHub Web

1. Rodar localmente: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --workspace`
2. Subir alterações na `main`.
3. Publicar a release em **GitHub → Releases → Draft a new release** (com o workflow `.github/workflows/release.yml` ativo, o binário Linux + `.sha256` são anexados automaticamente após clicar em **Publish release**).