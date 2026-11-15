use std::io::{self, Write};
use std::net::SocketAddr;

use zeroize::Zeroizing;

use falkon_core::crypto::{RoomSecret, constant_time_eq};
use falkon_core::protocol::HistoryRetention;
use falkon_core::sanitize::sanitize_nick;

#[derive(Debug)]
pub enum StartupMode {
    Host {
        listen_addr: String,
        nick: String,
        retention: HistoryRetention,
        secret: RoomSecret,
    },
    Peer {
        connect_addr: String,
        nick: String,
        secret: RoomSecret,
    },
    Preview {
        nick: String,
        retention: HistoryRetention,
    },
    Exit,
}

pub fn prompt_room_secret(confirm: bool) -> Result<Option<RoomSecret>, Box<dyn std::error::Error>> {
    loop {
        let mut raw = match rpassword::prompt_password("Segredo da sala (min. 12 chars, oculto): ")
        {
            Ok(s) => Zeroizing::new(s),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Box::new(e)),
        };

        let secret = match RoomSecret::new(std::mem::take(&mut *raw)) {
            Ok(s) => s,
            Err(e) => {
                println!("[!] {e}. Tente novamente.");
                continue;
            }
        };

        if confirm {
            let confirm_raw =
                match rpassword::prompt_password("Confirme o segredo da sala (oculto): ") {
                    Ok(s) => Zeroizing::new(s),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(e) => return Err(Box::new(e)),
                };

            if !constant_time_eq(secret.as_bytes(), confirm_raw.as_bytes()) {
                println!("[!] Os segredos nao coincidem. Tente novamente.");
                continue;
            }
        }

        return Ok(Some(secret));
    }
}

pub fn run_interactive_setup(
    default_nick: &str,
    default_retention: HistoryRetention,
) -> Result<StartupMode, Box<dyn std::error::Error>> {
    println!("==================================================");
    println!("  FALKON v0.4.0 — Chat P2P E2EE 100% Terminal");
    println!("==================================================");
    println!("Escolha como iniciar:");
    println!("  [1] Criar nova sala (Host)");
    println!("  [2] Entrar em uma sala existente (Peer)");
    println!("  [3] Modo Preview local (sem rede)");
    println!("  [0] Sair");
    println!();

    loop {
        let Some(choice) = read_line_trimmed("Opcao [1]: ")? else {
            return Ok(StartupMode::Exit);
        };

        match choice.as_str() {
            "" | "1" => {
                let Some(nick) = prompt_nick(default_nick)? else {
                    return Ok(StartupMode::Exit);
                };
                let Some(listen_addr) = prompt_listen_addr()? else {
                    return Ok(StartupMode::Exit);
                };
                let Some(retention) = prompt_retention(default_retention)? else {
                    return Ok(StartupMode::Exit);
                };
                let Some(secret) = prompt_room_secret(true)? else {
                    return Ok(StartupMode::Exit);
                };
                return Ok(StartupMode::Host {
                    listen_addr,
                    nick,
                    retention,
                    secret,
                });
            }
            "2" => {
                let Some(nick) = prompt_nick(default_nick)? else {
                    return Ok(StartupMode::Exit);
                };
                let Some(connect_addr) = prompt_connect_addr()? else {
                    return Ok(StartupMode::Exit);
                };
                let Some(secret) = prompt_room_secret(false)? else {
                    return Ok(StartupMode::Exit);
                };
                return Ok(StartupMode::Peer {
                    connect_addr,
                    nick,
                    secret,
                });
            }
            "3" => {
                let Some(nick) = prompt_nick(default_nick)? else {
                    return Ok(StartupMode::Exit);
                };
                return Ok(StartupMode::Preview {
                    nick,
                    retention: default_retention,
                });
            }
            "0" => return Ok(StartupMode::Exit),
            _ => println!("[!] Opcao invalida. Digite 1, 2, 3 ou 0."),
        }
    }
}

fn read_line_trimmed(prompt: &str) -> io::Result<Option<String>> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    let n = io::stdin().read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_owned()))
}

fn prompt_nick(default_nick: &str) -> io::Result<Option<String>> {
    loop {
        let prompt = format!("Seu apelido [{default_nick}]: ");
        let Some(raw) = read_line_trimmed(&prompt)? else {
            return Ok(None);
        };
        let candidate = if raw.is_empty() {
            default_nick.to_owned()
        } else {
            raw
        };
        match sanitize_nick(&candidate) {
            Ok(clean) => return Ok(Some(clean)),
            Err(e) => println!("[!] {e}. Tente outro apelido."),
        }
    }
}

fn prompt_listen_addr() -> io::Result<Option<String>> {
    println!("\nOnde a sala deve aceitar conexoes?");
    println!("  [1] Apenas neste PC (127.0.0.1:7777)");
    println!("  [2] Rede local / Wi-Fi / LAN (0.0.0.0:7777)");
    println!("  Ou digite IP:PORTA personalizado (ex.: 0.0.0.0:9000)");

    loop {
        let Some(raw) = read_line_trimmed("Endereco [1]: ")? else {
            return Ok(None);
        };
        match parse_listen_choice(&raw) {
            Some(addr) => return Ok(Some(addr)),
            None => println!("[!] Endereco invalido. Use 1, 2 ou IP:PORTA (ex.: 127.0.0.1:7777)."),
        }
    }
}

fn prompt_connect_addr() -> io::Result<Option<String>> {
    println!("\nInforme o IP:PORTA do Host (ex.: 127.0.0.1:7777 ou 192.168.1.45:7777)");
    loop {
        let Some(raw) = read_line_trimmed("Conectar em [127.0.0.1:7777]: ")? else {
            return Ok(None);
        };
        let candidate = if raw.is_empty() {
            "127.0.0.1:7777".to_owned()
        } else {
            raw
        };
        if candidate.parse::<SocketAddr>().is_ok() {
            return Ok(Some(candidate));
        }
        println!("[!] Formato invalido. Use IP:PORTA (ex.: 127.0.0.1:7777).");
    }
}

fn prompt_retention(default_retention: HistoryRetention) -> io::Result<Option<HistoryRetention>> {
    println!("\nCiclo de limpeza automatica das mensagens na RAM e tela:");
    println!("  [1] Nao limpar (mantem enquanto a sala estiver ativa)");
    println!("  [2] 5 segundos");
    println!("  [3] 15 segundos");
    println!("  [4] 60 segundos");

    let default_num = match default_retention {
        HistoryRetention::Never => "1",
        HistoryRetention::Secs5 => "2",
        HistoryRetention::Secs15 => "3",
        HistoryRetention::Secs60 => "4",
    };

    loop {
        let prompt = format!("Retencao [{default_num}]: ");
        let Some(raw) = read_line_trimmed(&prompt)? else {
            return Ok(None);
        };
        let effective = if raw.is_empty() { default_num } else { &raw };
        match parse_retention_choice(effective) {
            Some(r) => return Ok(Some(r)),
            None => println!("[!] Escolha 1, 2, 3 ou 4."),
        }
    }
}

pub fn parse_listen_choice(raw: &str) -> Option<String> {
    match raw.trim() {
        "" | "1" => Some("127.0.0.1:7777".to_owned()),
        "2" => Some("0.0.0.0:7777".to_owned()),
        other => other
            .parse::<SocketAddr>()
            .ok()
            .map(|addr| addr.to_string()),
    }
}

pub fn parse_retention_choice(raw: &str) -> Option<HistoryRetention> {
    match raw.trim() {
        "1" | "never" => Some(HistoryRetention::Never),
        "2" | "5s" => Some(HistoryRetention::Secs5),
        "3" | "15s" => Some(HistoryRetention::Secs15),
        "4" | "60s" => Some(HistoryRetention::Secs60),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_choices_and_custom_socket_addrs() {
        assert_eq!(parse_listen_choice(""), Some("127.0.0.1:7777".to_owned()));
        assert_eq!(parse_listen_choice("1"), Some("127.0.0.1:7777".to_owned()));
        assert_eq!(parse_listen_choice("2"), Some("0.0.0.0:7777".to_owned()));
        assert_eq!(
            parse_listen_choice("192.168.0.10:8888"),
            Some("192.168.0.10:8888".to_owned())
        );
        assert_eq!(parse_listen_choice("invalido"), None);
    }

    #[test]
    fn parses_retention_choices() {
        assert_eq!(parse_retention_choice("1"), Some(HistoryRetention::Never));
        assert_eq!(parse_retention_choice("2"), Some(HistoryRetention::Secs5));
        assert_eq!(parse_retention_choice("3"), Some(HistoryRetention::Secs15));
        assert_eq!(parse_retention_choice("4"), Some(HistoryRetention::Secs60));
        assert_eq!(parse_retention_choice("9"), None);
    }
}
