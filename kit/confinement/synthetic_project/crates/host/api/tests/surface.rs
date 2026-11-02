fn main() {
    assert_eq!(fixture_host_api::API_VERSION, 1);
    assert_eq!(fixture_host_api::describe("api"), "api@1");
}
