fn main() {
    let expected = cfg!(feature = "dev-uat-policy-import");
    assert_eq!(fixture_host_api::policy_import_enabled(), expected);
}
