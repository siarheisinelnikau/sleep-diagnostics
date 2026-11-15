use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("sleep-diagnostics.ico");
    let sizes = [16u32, 20, 24, 32, 48, 64, 256];
    let mut ico = vec![0, 0, 1, 0, sizes.len() as u8, 0];
    let mut images = Vec::new();
    let mut offset = (6 + sizes.len() * 16) as u32;
    for size in sizes {
        let mask_stride = size.div_ceil(32) * 4;
        let len = 40 + size * size * 4 + mask_stride * size;
        ico.extend([if size == 256 { 0 } else { size as u8 }; 2]);
        ico.extend([0, 0, 1, 0, 32, 0]);
        ico.extend(len.to_le_bytes());
        ico.extend(offset.to_le_bytes());
        offset += len;
        let mut bmp = Vec::new();
        for value in [40u32, size, size * 2] {
            bmp.extend(value.to_le_bytes());
        }
        bmp.extend([1, 0, 32, 0]);
        for value in [0u32, size * size * 4, 0, 0, 0, 0] {
            bmp.extend(value.to_le_bytes());
        }
        for y in (0..size).rev() {
            for x in 0..size {
                let px = (x as f32 + 0.5) / size as f32;
                let py = (y as f32 + 0.5) / size as f32;
                let r = ((px - 0.5).powi(2) + (py - 0.5).powi(2)).sqrt();
                let cut = ((px - 0.66).powi(2) + (py - 0.30).powi(2)).sqrt();
                let moon = r < 0.39 && cut > 0.32;
                let dot = ((px - 0.75).powi(2) + (py - 0.68).powi(2)).sqrt() < 0.07;
                bmp.extend(if moon {
                    [196, 147, 59, 255]
                } else if dot {
                    [128, 203, 161, 255]
                } else {
                    [0, 0, 0, 0]
                });
            }
        }
        bmp.resize(len as usize, 0);
        images.extend(bmp);
    }
    ico.extend(images);
    fs::write(&path, ico).unwrap();
    let mut resource = winresource::WindowsResource::new();
    resource.set_icon(path.to_str().unwrap());
    resource.set("ProductName", "Sleep Diagnostics");
    resource.set(
        "FileDescription",
        "Sleep Diagnostics — Windows power evidence",
    );
    resource.set("LegalCopyright", "MIT License");
    resource.set_manifest(r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity version="0.1.0.0" processorArchitecture="*" name="SleepDiagnostics" type="win32"/><dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo><application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings><dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness><longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware></windowsSettings></application></assembly>"#);
    resource.compile().expect("Windows resources");
}
