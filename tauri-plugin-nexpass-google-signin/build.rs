const COMMANDS: &[&str] = &["sign_in", "sign_out", "get_current_user", "is_available"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}