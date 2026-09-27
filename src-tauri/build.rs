#[cfg(feature = "desktop")]
fn main() {
    let attributes = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
    tauri_build::try_build(attributes).expect("Tauri build setup failed");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    println!("cargo:rerun-if-changed=windows-app.manifest");
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("windows-app.manifest");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // Unlike Tauri's bin-only resources, these also reach library unit-test executables.
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    } else {
        // GCC appends default-manifest.o. Supply our complete manifest through a local
        // search prefix, avoiding two competing RT_MANIFEST resources (MinGW ld 34362).
        // Never change the installed toolchain's default-manifest.o.
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        let rc = out.join("dsw-manifest.rc");
        std::fs::write(
            &rc,
            format!(
                "1 24 \"{}\"\n",
                manifest.display().to_string().replace('\\', "/")
            ),
        )
        .expect("write manifest resource");
        println!("cargo:rerun-if-env-changed=WINDRES");
        let compiler = std::env::var_os("WINDRES").unwrap_or_else(|| "windres".into());
        let result = std::process::Command::new(compiler)
            .arg("--input-format=rc")
            .arg("--output-format=coff")
            .arg("--codepage=65001")
            .arg(&rc)
            .arg(out.join("default-manifest.o"))
            .output()
            .expect("windres is required for Windows GNU desktop builds");
        assert!(
            result.status.success(),
            "manifest compilation failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        println!(
            "cargo:rustc-link-arg=-B{}/",
            out.display().to_string().replace('\\', "/")
        );
    }
}

#[cfg(not(feature = "desktop"))]
fn main() {}
