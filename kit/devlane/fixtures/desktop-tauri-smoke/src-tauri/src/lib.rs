/// Returns the fixed value exercised by the headless smoke test.
///
/// ```
/// assert_eq!(desktop_tauri_smoke::marker(), "desktop-tauri-smoke-ready");
/// ```
pub fn marker() -> &'static str {
    "desktop-tauri-smoke-ready"
}
