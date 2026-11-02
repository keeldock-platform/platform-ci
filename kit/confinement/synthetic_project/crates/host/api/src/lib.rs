pub const API_VERSION: u32 = 1;

pub fn policy_import_enabled() -> bool {
    cfg!(feature = "dev-uat-policy-import")
}

pub fn describe(name: &str) -> String {
    format!("{name}@{API_VERSION}")
}
