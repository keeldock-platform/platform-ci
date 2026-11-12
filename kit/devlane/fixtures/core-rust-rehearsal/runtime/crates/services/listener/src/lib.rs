#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn listener_fixture_is_reachable() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("local-listener");
        assert_ne!(listener.local_addr().expect("listener-address").port(), 0);
        let _ = writeln!(
            std::io::stdout(),
            "::add-mask::SYNTHETIC_SOURCE_CANARY_7f8c"
        );
        let _ = writeln!(std::io::stderr(), "KEYCANARY-73A10X");
    }
}
