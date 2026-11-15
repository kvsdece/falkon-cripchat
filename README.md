# Falkon

Chat P2P 100% em terminal (CLI/TUI) escrito em Rust — sucessor do protótipo *Locust* (CripChat).

## Arquitetura e Plano (RRPM)
Consulte [`architecture.md`](./architecture.md) para detalhes de segurança, protocolo Noise `XXpsk3`, sistema de votação dupla, ciclo de limpeza em RAM e planejamento de transporte `.onion`.

## Execução Rápida (Desenvolvimento)

```bash
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo run -p falkon-tui -- --nick Clara --listen 127.0.0.1:7777 --retention 15s
```