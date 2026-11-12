use std::io::Write;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut canaries = vec![
        "SYNTHETIC_SOURCE_CANARY_7f8c",
        "KEYCANARY-73A10X",
        "::add-mask::SYNTHETIC_SOURCE_CANARY_7f8c",
        "::error::SYNTHETIC_SOURCE_CANARY_7f8c",
        "::set-output name=x::SYNTHETIC_SOURCE_CANARY_7f8c",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let group = format!(
        "{}{}[group]SYNTHETIC_SOURCE_CANARY_7f8c",
        char::from(35),
        char::from(35),
    );
    canaries.push(group);
    for canary in canaries {
        println!("cargo:warning={canary}");
        let _ = writeln!(std::io::stderr(), "{canary}");
    }
}
