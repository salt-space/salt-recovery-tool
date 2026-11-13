fn main() {
    // Tauri sets DEP_TAURI_DEV via its build script (`true` = load devUrl).
    // Plain `cargo build --release` stays in dev mode; only `tauri build` /
    // `npm run build` flips it off and embeds frontendDist.
    let dev = std::env::var("DEP_TAURI_DEV").map_or(true, |value| value == "true");
    if dev && std::env::var("PROFILE").as_deref() == Ok("release") {
        println!(
            "cargo:warning=release build is still in Tauri dev mode: the GUI will load \
             http://localhost:5173 instead of embedded assets. Use `npm run build` \
             (tauri build) for a shippable binary."
        );
    }

    tauri_build::build()
}
