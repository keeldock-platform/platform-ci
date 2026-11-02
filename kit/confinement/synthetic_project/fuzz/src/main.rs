const CORPUS: [&str; 3] = ["alpha=1", "beta=2", "gamma=3"];

fn parse(line: &str) -> Option<(&str, u32)> {
    let (key, value) = line.split_once('=')?;
    let number = value.parse().ok()?;
    Some((key, number))
}

fn main() {
    let mut total = 0;
    for line in CORPUS {
        let (_, number) = parse(line).expect("corpus entry rejected");
        total += number;
    }
    assert_eq!(total, 6);
    println!("replayed {}", CORPUS.len());
}
