// ── Shared utilities ────────────────────────────────────────────────────

/// Find the end of HTTP headers (`\r\n\r\n` or `\n\n`) in `buf`.
///
/// `start_pos` is a hint for where to start searching (for incremental reads);
/// pass 0 to search from the beginning.
pub fn find_header_separator(buf: &[u8], start_pos: usize) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    let start = start_pos.saturating_sub(3);
    for i in start..buf.len() - 1 {
        if buf[i] == b'\n' {
            if buf[i + 1] == b'\n' {
                return Some(i + 2);
            }
            if i + 2 < buf.len() && buf[i + 1] == b'\r' && buf[i + 2] == b'\n' {
                return Some(i + 3);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_header_separator() {
        let b1 = b"Host: localhost\r\n\r\n";
        assert_eq!(find_header_separator(b1, 0), Some(b1.len()));

        let b2 = b"Host: localhost\n\n";
        assert_eq!(find_header_separator(b2, 0), Some(b2.len()));

        let b3 = b"Host: localhost\r\n\n";
        assert_eq!(find_header_separator(b3, 0), Some(b3.len()));

        let b4 = b"Host: localhost\n\r\n";
        assert_eq!(find_header_separator(b4, 0), Some(b4.len()));

        let b5 = b"Host: localhost\r\n";
        assert_eq!(find_header_separator(b5, 0), None);

        // Test start_pos optimization
        let b6 = b"Host: localhost\r\n\r\nLeftover data";
        assert_eq!(find_header_separator(b6, 15), Some(19));
    }
}
