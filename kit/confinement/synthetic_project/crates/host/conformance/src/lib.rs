pub fn conforms() -> bool {
    let expected = fixture_host_api::describe("mock");
    fixture_host_mock::mock_name() == expected
}
