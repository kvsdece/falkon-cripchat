use crate::error::FalkonError;

pub const MAX_NICK_CHARS: usize = 24;
pub const MAX_MSG_CHARS: usize = 2048;

pub fn strip_ansi_and_controls(input: &str, allow_newlines: bool) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    let _ = chars.next();
                    for next_c in chars.by_ref() {
                        if ('@'..='~').contains(&next_c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    let _ = chars.next();
                    while let Some(next_c) = chars.next() {
                        if next_c == '\x07' {
                            break;
                        }
                        if next_c == '\x1b' && chars.peek().copied() == Some('\\') {
                            let _ = chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    let _ = chars.next();
                }
                None => {}
            }
            continue;
        }

        if c == '\n' && allow_newlines {
            out.push('\n');
            continue;
        }

        if c.is_control() {
            continue;
        }

        out.push(c);
    }

    out
}

pub fn sanitize_nick(raw: &str) -> Result<String, FalkonError> {
    let cleaned = strip_ansi_and_controls(raw, false);
    let trimmed: String = cleaned.trim().chars().take(MAX_NICK_CHARS).collect();
    if trimmed.is_empty() {
        return Err(FalkonError::InvalidInput("apelido vazio apos sanitizacao"));
    }
    Ok(trimmed)
}

pub fn sanitize_message(raw: &str) -> Result<String, FalkonError> {
    let cleaned = strip_ansi_and_controls(raw, true);
    let limited: String = cleaned.trim_end().chars().take(MAX_MSG_CHARS).collect();
    if limited.trim().is_empty() {
        return Err(FalkonError::InvalidInput("mensagem vazia"));
    }
    Ok(limited)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_and_osc_ansi_sequences() -> Result<(), FalkonError> {
        let evil = "\x1b[31m\x1b]0;HackTitle\x07Falkon\x1b[0m\r\n";
        let nick = sanitize_nick(evil)?;
        assert_eq!(nick, "Falkon");
        Ok(())
    }

    #[test]
    fn preserves_clean_multiline_message() -> Result<(), FalkonError> {
        let raw = "Ola!\x1b[2J\x07\nTudo certo.";
        let msg = sanitize_message(raw)?;
        assert_eq!(msg, "Ola!\nTudo certo.");
        Ok(())
    }
}
