use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    const ICON: &str = "../../packaging/assets/runonmine.ico";
    println!("cargo:rerun-if-changed={ICON}");
    println!("cargo:rerun-if-env-changed=RC_PATH");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return Ok(());
    }

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();
    if target_env == "msvc" && !host.contains("windows") {
        println!(
            "cargo:warning=skipping MSVC resource embedding on non-Windows host; native Windows builds require the Windows SDK"
        );
        return Ok(());
    }

    let mut resource = winresource::WindowsResource::new();
    resource
        .set_icon(ICON)
        .set("ProductName", "RunOnMine")
        .set("FileDescription", "RunOnMine security control center")
        .set("OriginalFilename", "runonmine-desktop.exe")
        .set("CompanyName", "RunOnMine contributors")
        .set_manifest(
            r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>"#,
        )
        .compile()?;
    Ok(())
}
