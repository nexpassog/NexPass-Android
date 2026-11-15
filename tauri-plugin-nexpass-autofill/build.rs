const COMMANDS: &[&str] = &["open_autofill_settings", "autofill_status"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}
