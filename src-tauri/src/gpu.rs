//! GPU / compute device detection.
//!
//! Detection leans on the bundled Hashcat backend query (`hashcat -I`),
//! which enumerates OpenCL and CUDA devices the engine can actually use.
//! The UI shows the friendly name and whether acceleration is available;
//! no driver configuration is ever exposed.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceKind {
    Gpu,
    Cpu,
    Other,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub name: String,
    pub kind: DeviceKind,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuInfo {
    pub devices: Vec<DeviceInfo>,
    /// "gpu" when a GPU is available, "cpu" otherwise, "none" when unknown.
    pub acceleration: &'static str,
}

impl DeviceKind {
    fn from_label(label: &str) -> DeviceKind {
        match label.trim().to_ascii_uppercase().as_str() {
            "GPU" => DeviceKind::Gpu,
            "CPU" => DeviceKind::Cpu,
            _ => DeviceKind::Other,
        }
    }
}

/// Enumerate compute devices through the bundled Hashcat. Never fails: a
/// broken backend reports no devices instead of erroring.
pub fn detect() -> GpuInfo {
    let output = std::process::Command::new(resolve_hashcat())
        .arg("-I")
        .arg("--force")
        .output();

    let devices = match output {
        Ok(out) => parse_devices(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => Vec::new(),
    };

    let acceleration = if devices.iter().any(|d| d.kind == DeviceKind::Gpu) {
        "gpu"
    } else if !devices.is_empty() {
        "cpu"
    } else {
        "none"
    };

    GpuInfo {
        devices,
        acceleration,
    }
}

/// Parse the `hashcat -I` device listing. Pure so it is unit-testable.
fn parse_devices(text: &str) -> Vec<DeviceInfo> {
    let mut devices = Vec::new();
    let mut in_opencl_block = false;
    let mut pending_name: Option<String> = None;
    let mut pending_kind = DeviceKind::Other;

    for line in text.lines() {
        let trimmed = line.trim_start();
        if line.starts_with("  Backend Device ID") {
            in_opencl_block = true;
            continue;
        }
        if in_opencl_block && line.starts_with("  ") {
            if let Some(value) = value_after(trimmed, "Type...........:") {
                pending_kind = DeviceKind::from_label(value);
            }
            if let Some(value) = value_after(trimmed, "Name...........:") {
                pending_name = Some(value.trim().to_string());
            }
            if pending_name.is_some() && pending_kind != DeviceKind::Other {
                if let Some(name) = pending_name.take() {
                    devices.push(DeviceInfo {
                        name,
                        kind: pending_kind,
                    });
                }
                in_opencl_block = false;
            }
            continue;
        }
        // CUDA-style device lines: `* Device #1: Name, ...`.
        if line.starts_with("* Device #") {
            if let Some((_, name)) = line.split_once(':') {
                let name = name.split(',').next().unwrap_or("").trim();
                if !name.is_empty() {
                    devices.push(DeviceInfo {
                        name: name.to_string(),
                        kind: DeviceKind::Gpu,
                    });
                }
            }
        }
    }
    devices
}

fn value_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let value = line.strip_prefix(marker)?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Resolve the hashcat binary for backend detection. Reuses the engine's
/// program lookup so packaged and development layouts agree.
fn resolve_hashcat() -> std::path::PathBuf {
    crate::engine::resolve_program("hashcat").unwrap_or_else(|| "hashcat".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_opencl_cpu_block() {
        let text = "OpenCL Platform ID #1\n  Vendor..: The pocl project\n  Backend Device ID #1\n    Type...........: CPU\n    Name...........: cpu-haswell-Intel(R) Core(TM) Ultra 7 265K\n";
        let devices = parse_devices(text);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].kind, DeviceKind::Cpu);
        assert!(devices[0].name.contains("Intel"));
    }

    #[test]
    fn parses_cuda_device_line() {
        let text = "* Device #1: NVIDIA GeForce RTX 5070 Ti, 16383/16384 MB\n";
        let devices = parse_devices(text);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].kind, DeviceKind::Gpu);
        assert_eq!(devices[0].name, "NVIDIA GeForce RTX 5070 Ti");
    }

    #[test]
    fn empty_output_reports_none() {
        assert!(parse_devices("").is_empty());
    }

    #[test]
    fn device_kind_from_label() {
        assert_eq!(DeviceKind::from_label("GPU"), DeviceKind::Gpu);
        assert_eq!(DeviceKind::from_label("cpu"), DeviceKind::Cpu);
        assert_eq!(DeviceKind::from_label("FPGA"), DeviceKind::Other);
    }
}
