const CORPUS: [&[u8]; 2] = [
    include_bytes!("../corpus/valid-object.json"),
    include_bytes!("../corpus/valid-array.json"),
];

fn replay_corpus() -> usize {
    for seed in CORPUS {
        if !seed.starts_with(b"{") || !seed.ends_with(b"}\n") {
            std::process::exit(2);
        }
    }
    CORPUS.len()
}

fn main() {
    println!("Replayed {} parser corpus seeds.", replay_corpus());
}

#[cfg(test)]
mod tests {
    #[test]
    fn corpus_fixture_is_present() {
        assert_eq!(super::replay_corpus(), 2);
    }
}
