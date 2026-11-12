// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

//! Keep an upstream proxy out of a machine-wide VPN/TUN route on Windows.
//!
//! A profile still uses its proxy for every browser request. This only changes
//! the first hop -- PiBrowse to the proxy server -- so a TUN client cannot put
//! one proxy inside another and break the upstream handshake.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Report {
    pub supported: bool,
    pub changed: bool,
    pub addresses: Vec<String>,
    pub interface_index: Option<u32>,
    pub gateway: Option<String>,
}

#[cfg(not(target_os = "windows"))]
pub fn ensure(_hosts: &[String]) -> Result<Report, String> {
    Ok(Report {
        supported: false,
        changed: false,
        addresses: Vec::new(),
        interface_index: None,
        gateway: None,
    })
}

#[cfg(target_os = "windows")]
mod windows {
    use super::Report;
    use base64::Engine;
    use serde::Deserialize;
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
    use std::process::Command;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Snapshot {
        interface_index: u32,
        next_hop: String,
        #[serde(default)]
        existing: Vec<String>,
    }

    pub fn ensure(hosts: &[String]) -> Result<Report, String> {
        let addresses = resolve(hosts)?;
        if addresses.is_empty() {
            return Err("The proxy address did not resolve to an IPv4 address.".into());
        }

        let before = snapshot(&addresses)?;
        let existing: BTreeSet<&str> = before.existing.iter().map(String::as_str).collect();
        let missing: Vec<Ipv4Addr> = addresses
            .iter()
            .copied()
            .filter(|ip| !existing.contains(format!("{ip}/32").as_str()))
            .collect();

        if missing.is_empty() {
            return Ok(report(false, &addresses, &before));
        }

        add_elevated(&missing, &before.next_hop, before.interface_index)?;

        // Do not trust route.exe's exit status alone: a VPN client can race an
        // auto-route refresh. The rule is complete only when Windows reports
        // every /32 on the physical default interface we selected.
        let after = snapshot(&addresses)?;
        let now: BTreeSet<&str> = after.existing.iter().map(String::as_str).collect();
        let absent: Vec<String> = addresses
            .iter()
            .filter_map(|ip| {
                let prefix = format!("{ip}/32");
                (!now.contains(prefix.as_str())).then_some(ip.to_string())
            })
            .collect();
        if !absent.is_empty() {
            return Err(format!(
                "Windows accepted the route command, but these proxy addresses are not on the physical interface: {}",
                absent.join(", ")
            ));
        }
        Ok(report(true, &addresses, &after))
    }

    fn report(changed: bool, addresses: &[Ipv4Addr], snap: &Snapshot) -> Report {
        Report {
            supported: true,
            changed,
            addresses: addresses.iter().map(ToString::to_string).collect(),
            interface_index: Some(snap.interface_index),
            gateway: Some(snap.next_hop.clone()),
        }
    }

    fn resolve(hosts: &[String]) -> Result<Vec<Ipv4Addr>, String> {
        let mut out = BTreeSet::new();
        for raw in hosts {
            let host = raw.trim().trim_start_matches('[').trim_end_matches(']');
            if host.is_empty() {
                continue;
            }
            if let Ok(ip) = host.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(ip) => {
                        validate(ip)?;
                        out.insert(ip);
                    }
                    IpAddr::V6(_) => {
                        return Err(format!(
                            "{host} is IPv6. Automatic VPN/TUN bypass currently supports IPv4 proxy servers only."
                        ));
                    }
                }
                continue;
            }

            let resolved = (host, 0)
                .to_socket_addrs()
                .map_err(|e| format!("Could not resolve proxy server {host}: {e}"))?;
            let mut found = false;
            for socket in resolved {
                if let IpAddr::V4(ip) = socket.ip() {
                    validate(ip)?;
                    out.insert(ip);
                    found = true;
                }
            }
            if !found {
                return Err(format!("Proxy server {host} has no IPv4 address."));
            }
        }
        Ok(out.into_iter().collect())
    }

    fn validate(ip: Ipv4Addr) -> Result<(), String> {
        if ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() {
            return Err(format!("{ip} is not a routable proxy server address."));
        }
        Ok(())
    }

    fn snapshot(addresses: &[Ipv4Addr]) -> Result<Snapshot, String> {
        let targets = ps_array(
            &addresses
                .iter()
                .map(|ip| format!("{ip}/32"))
                .collect::<Vec<_>>(),
        );
        // `Get-NetAdapter -Physical` is the important boundary. Selecting the
        // numerically cheapest default route would select sing-box/Wintun --
        // precisely the path this feature is meant to avoid.
        let script = format!(
            r#"$ErrorActionPreference='Stop';
$physical=@(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object InterfaceIndex);
$route=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {{ $_.NextHop -ne '0.0.0.0' -and $physical -contains $_.InterfaceIndex }} | ForEach-Object {{ $m=(Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $_.InterfaceIndex -ErrorAction Stop).InterfaceMetric; [pscustomobject]@{{ InterfaceIndex=$_.InterfaceIndex; NextHop=$_.NextHop; TotalMetric=([int]$_.RouteMetric+[int]$m) }} }} | Sort-Object TotalMetric | Select-Object -First 1;
if ($null -eq $route) {{ throw 'No active physical IPv4 default route was found. Connect Ethernet or Wi-Fi first.' }};
$targets={targets};
$existing=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {{ $targets -contains $_.DestinationPrefix -and $_.InterfaceIndex -eq $route.InterfaceIndex -and $_.NextHop -eq $route.NextHop }} | ForEach-Object DestinationPrefix);
[pscustomobject]@{{ InterfaceIndex=[int]$route.InterfaceIndex; NextHop=[string]$route.NextHop; Existing=@($existing) }} | ConvertTo-Json -Compress"#
        );
        let output = powershell(&script)?;
        serde_json::from_str(output.trim().trim_start_matches('\u{feff}'))
            .map_err(|e| format!("Could not read the Windows route table: {e}"))
    }

    fn add_elevated(addresses: &[Ipv4Addr], gateway: &str, interface: u32) -> Result<(), String> {
        // Values interpolated into this script have already been parsed as IP
        // addresses or integers. The original host string never reaches a
        // shell, so a pasted proxy cannot turn an elevation prompt into command
        // execution.
        let ips = ps_array(
            &addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        );
        let admin_script = format!(
            r#"$ErrorActionPreference='Stop';
foreach ($ip in {ips}) {{
  & "$env:SystemRoot\System32\route.exe" -p ADD $ip MASK 255.255.255.255 {gateway} METRIC 1 IF {interface} | Out-Null;
  if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
}}
exit 0"#
        );
        let encoded = encode_powershell(&admin_script);
        let launcher = format!(
            r#"$ErrorActionPreference='Stop'; $p=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','{encoded}'); exit $p.ExitCode"#
        );
        powershell(&launcher).map(|_| ()).map_err(|e| {
            format!(
                "Could not add the Windows VPN/TUN bypass route. Approve the administrator prompt and try again. {e}"
            )
        })
    }

    fn powershell(script: &str) -> Result<String, String> {
        let output = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .output()
            .map_err(|e| format!("Could not start Windows PowerShell: {e}"))?;
        if output.status.success() {
            return decode_output(&output.stdout);
        }
        let detail = decode_output(&output.stderr)
            .or_else(|_| decode_output(&output.stdout))
            .unwrap_or_else(|_| format!("exit code {}", output.status.code().unwrap_or(-1)));
        Err(detail.trim().to_string())
    }

    fn decode_output(bytes: &[u8]) -> Result<String, String> {
        match String::from_utf8(bytes.to_vec()) {
            Ok(s) => Ok(s),
            Err(_) if bytes.len() % 2 == 0 => {
                let words: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                String::from_utf16(&words).map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn ps_array(values: &[String]) -> String {
        let quoted = values
            .iter()
            .map(|v| format!("'{}'", v.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        format!("@({quoted})")
    }

    fn encode_powershell(script: &str) -> String {
        let mut bytes = Vec::with_capacity(script.len() * 2);
        for word in script.encode_utf16() {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn elevated_script_is_utf16_base64() {
            assert_eq!(encode_powershell("exit 0"), "ZQB4AGkAdAAgADAA");
        }

        #[test]
        fn powershell_arrays_quote_values() {
            assert_eq!(
                ps_array(&["1.2.3.4/32".into(), "5.6.7.8/32".into()]),
                "@('1.2.3.4/32','5.6.7.8/32')"
            );
        }

        #[test]
        fn unsafe_addresses_are_refused_before_elevation() {
            assert!(validate(Ipv4Addr::LOCALHOST).is_err());
            assert!(validate(Ipv4Addr::UNSPECIFIED).is_err());
            assert!(validate(Ipv4Addr::new(163, 123, 201, 81)).is_ok());
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows::ensure;
