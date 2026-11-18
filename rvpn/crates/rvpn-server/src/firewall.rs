// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Fail-closed host containment and NAT for server-side TUN egress.

// Platform implementations share helpers so both can be tested on one host.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use tracing::warn;

use crate::config::ServerConfig;
use crate::egress::{self, normalized_tun_subnet, Cidr, BLOCKED_IPV4_CIDRS, BLOCKED_IPV6_CIDRS};

const INPUT_CHAIN: &str = "RVPN_INPUT";
const FORWARD_CHAIN: &str = "RVPN_FORWARD";
const NAT_CHAIN: &str = "RVPN_NAT";
const PF_ANCHOR_PATH: &str = "/usr/local/etc/rvpn/rvpn.anchor.conf";

struct CommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

trait CommandRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput>;
}

struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
        let output = Command::new(program).args(args).output()?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Configure containment before TUN starts; any failure aborts server startup.
pub fn setup_tun_egress(config: &ServerConfig) -> Result<()> {
    let subnet = normalized_tun_subnet(&config.tun.tun_ip)?;
    let allowed_ranges = parse_allowed_ranges(&config.network.allowed_internal_ranges)?;
    let allow_c2c = config.network.allow_client_to_client;
    let mut runner = SystemRunner;

    #[cfg(target_os = "linux")]
    {
        let forwarding = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("Cannot verify net.ipv4.ip_forward; refusing uncontained TUN startup")?;
        if forwarding.trim() != "1" {
            anyhow::bail!("net.ipv4.ip_forward is disabled; enable it before starting TUN mode");
        }
        setup_linux_firewall(
            &mut runner,
            &config.tun.interface_name,
            &subnet,
            config.network.nat_enabled,
            &config.network.public_addresses,
            allow_c2c,
            &allowed_ranges,
        )
    }

    #[cfg(target_os = "freebsd")]
    {
        setup_freebsd_firewall(
            &mut runner,
            &config.tun.interface_name,
            &subnet,
            config.network.nat_enabled,
            &config.network.public_addresses,
            allow_c2c,
            &allowed_ranges,
            Path::new(PF_ANCHOR_PATH),
        )
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (&mut runner, subnet, allowed_ranges, allow_c2c);
        anyhow::bail!("TUN egress containment is supported only on Linux and FreeBSD")
    }
}

/// Parse the operator allow-list (validated at startup by
/// [`egress::ClientEgressPolicy::from_config`]; re-parsed here so the firewall
/// layer never trusts an unchecked string).
fn parse_allowed_ranges(ranges: &[String]) -> Result<Vec<Cidr>> {
    ranges
        .iter()
        .map(|text| {
            egress::parse_cidr(text)
                .with_context(|| format!("Invalid allowed_internal_ranges entry: {text}"))
        })
        .collect()
}

fn run_checked(
    runner: &mut dyn CommandRunner,
    program: &str,
    args: &[&str],
) -> Result<CommandOutput> {
    let output = runner.run(program, args).with_context(|| {
        format!("Failed to execute {program}; install it and verify TUN firewall prerequisites")
    })?;
    if !output.success {
        anyhow::bail!(
            "{} {} failed: {}{}",
            program,
            args.join(" "),
            output.stderr.trim(),
            output.stdout.trim()
        );
    }
    Ok(output)
}

fn setup_linux_firewall(
    runner: &mut dyn CommandRunner,
    tun_interface: &str,
    subnet: &str,
    nat_enabled: bool,
    public_addresses: &[std::net::IpAddr],
    allow_c2c: bool,
    allowed_ranges: &[Cidr],
) -> Result<()> {
    validate_interface(tun_interface)?;
    setup_linux_filter_family(
        runner,
        "iptables",
        tun_interface,
        Some(subnet),
        BLOCKED_IPV4_CIDRS,
        public_addresses,
        allow_c2c,
        allowed_ranges,
    )?;
    setup_linux_filter_family(
        runner,
        "ip6tables",
        tun_interface,
        None,
        BLOCKED_IPV6_CIDRS,
        public_addresses,
        allow_c2c,
        allowed_ranges,
    )?;

    if nat_enabled {
        let egress_interface = detect_linux_interface(runner)?;
        setup_linux_nat(runner, subnet, &egress_interface)?;
    } else {
        disable_linux_nat(runner, subnet)?;
    }
    Ok(())
}

fn setup_linux_filter_family(
    runner: &mut dyn CommandRunner,
    program: &str,
    tun_interface: &str,
    subnet: Option<&str>,
    blocked_cidrs: &[&str],
    public_addresses: &[std::net::IpAddr],
    allow_c2c: bool,
    allowed_ranges: &[Cidr],
) -> Result<()> {
    ensure_owned_chain(runner, program, &[], INPUT_CHAIN)?;
    run_checked(
        runner,
        program,
        &["-w", "-A", INPUT_CHAIN, "-i", tun_interface, "-j", "DROP"],
    )?;
    replace_jump(
        runner,
        program,
        &[],
        "INPUT",
        &["-i", tun_interface, "-j", INPUT_CHAIN],
    )?;

    ensure_owned_chain(runner, program, &[], FORWARD_CHAIN)?;
    // Configured public addresses (1:1 NAT) are not on any interface, so the
    // interface-address blocks above cannot see them — drop them explicitly
    // to stop kernel-forwarded TUN traffic looping back through the NAT.
    // These drops stay AHEAD of every exemption: the host is never reachable.
    for address in public_addresses {
        if address.is_ipv4() != (program == "iptables") {
            continue;
        }
        run_checked(
            runner,
            program,
            &[
                "-w",
                "-A",
                FORWARD_CHAIN,
                "-i",
                tun_interface,
                "-d",
                &address.to_string(),
                "-j",
                "DROP",
            ],
        )?;
    }
    // C24 opt-in exemptions, inserted BEFORE the special-use drops so they
    // actually match (first-match wins). Client-to-client is pool-specific —
    // never a re-opening of 10/8 — and both directions stay on the tunnel.
    if allow_c2c {
        if let Some(subnet) = subnet {
            run_checked(
                runner,
                program,
                &[
                    "-w",
                    "-A",
                    FORWARD_CHAIN,
                    "-i",
                    tun_interface,
                    "-o",
                    tun_interface,
                    "-s",
                    subnet,
                    "-d",
                    subnet,
                    "-j",
                    "ACCEPT",
                ],
            )?;
        }
    }
    for (network, prefix) in allowed_ranges {
        if network.is_ipv4() != (program == "iptables") {
            continue;
        }
        let cidr = format!("{network}/{prefix}");
        run_checked(
            runner,
            program,
            &[
                "-w",
                "-A",
                FORWARD_CHAIN,
                "-i",
                tun_interface,
                "-d",
                &cidr,
                "-j",
                "ACCEPT",
            ],
        )?;
    }
    for cidr in blocked_cidrs {
        run_checked(
            runner,
            program,
            &[
                "-w",
                "-A",
                FORWARD_CHAIN,
                "-i",
                tun_interface,
                "-d",
                cidr,
                "-j",
                "DROP",
            ],
        )?;
    }

    let mut outbound = vec!["-w", "-A", FORWARD_CHAIN, "-i", tun_interface];
    if let Some(subnet) = subnet {
        outbound.extend(["-s", subnet]);
        outbound.extend(["-j", "ACCEPT"]);
        run_checked(runner, program, &outbound)?;
    }
    // Without a source subnet (the ip6tables family) there is no IPv6 client
    // pool yet, so nothing from the TUN interface is forwarded at all — the
    // catch-all drops below dispose of it, matching the pf posture.

    let mut inbound = vec![
        "-w",
        "-A",
        FORWARD_CHAIN,
        "-o",
        tun_interface,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
    ];
    if let Some(subnet) = subnet {
        inbound.extend(["-d", subnet]);
    }
    inbound.extend(["-j", "ACCEPT"]);
    run_checked(runner, program, &inbound)?;
    run_checked(
        runner,
        program,
        &["-w", "-A", FORWARD_CHAIN, "-o", tun_interface, "-j", "DROP"],
    )?;
    run_checked(
        runner,
        program,
        &["-w", "-A", FORWARD_CHAIN, "-i", tun_interface, "-j", "DROP"],
    )?;

    replace_jump(
        runner,
        program,
        &[],
        "FORWARD",
        &["-i", tun_interface, "-j", FORWARD_CHAIN],
    )?;
    replace_jump(
        runner,
        program,
        &[],
        "FORWARD",
        &["-o", tun_interface, "-j", FORWARD_CHAIN],
    )?;
    Ok(())
}

fn setup_linux_nat(
    runner: &mut dyn CommandRunner,
    subnet: &str,
    egress_interface: &str,
) -> Result<()> {
    validate_interface(egress_interface)?;
    let table = ["-t", "nat"];
    ensure_owned_chain(runner, "iptables", &table, NAT_CHAIN)?;
    run_checked(
        runner,
        "iptables",
        &[
            "-w",
            "-t",
            "nat",
            "-A",
            NAT_CHAIN,
            "-s",
            subnet,
            "-o",
            egress_interface,
            "-j",
            "MASQUERADE",
        ],
    )?;
    replace_jump(
        runner,
        "iptables",
        &table,
        "POSTROUTING",
        &["-s", subnet, "-j", NAT_CHAIN],
    )
}

fn disable_linux_nat(runner: &mut dyn CommandRunner, subnet: &str) -> Result<()> {
    let table = ["-t", "nat"];
    if chain_exists(runner, "iptables", &table, NAT_CHAIN)? {
        remove_jump(
            runner,
            "iptables",
            &table,
            "POSTROUTING",
            &["-s", subnet, "-j", NAT_CHAIN],
        )?;
        run_checked(runner, "iptables", &["-w", "-t", "nat", "-F", NAT_CHAIN])?;
    }
    Ok(())
}

fn chain_exists(
    runner: &mut dyn CommandRunner,
    program: &str,
    table: &[&str],
    chain: &str,
) -> Result<bool> {
    let mut args = vec!["-w"];
    args.extend(table);
    args.extend(["-L", chain]);
    Ok(runner.run(program, &args)?.success)
}

fn ensure_owned_chain(
    runner: &mut dyn CommandRunner,
    program: &str,
    table: &[&str],
    chain: &str,
) -> Result<()> {
    if !chain_exists(runner, program, table, chain)? {
        let mut args = vec!["-w"];
        args.extend(table);
        args.extend(["-N", chain]);
        run_checked(runner, program, &args)?;
    }
    let mut args = vec!["-w"];
    args.extend(table);
    args.extend(["-F", chain]);
    run_checked(runner, program, &args).map(|_| ())
}

fn replace_jump(
    runner: &mut dyn CommandRunner,
    program: &str,
    table: &[&str],
    parent: &str,
    rule: &[&str],
) -> Result<()> {
    remove_jump(runner, program, table, parent, rule)?;
    let mut args = vec!["-w"];
    args.extend(table);
    args.extend(["-I", parent, "1"]);
    args.extend(rule);
    run_checked(runner, program, &args).map(|_| ())
}

fn remove_jump(
    runner: &mut dyn CommandRunner,
    program: &str,
    table: &[&str],
    parent: &str,
    rule: &[&str],
) -> Result<()> {
    loop {
        let mut check = vec!["-w"];
        check.extend(table);
        check.extend(["-C", parent]);
        check.extend(rule);
        if !runner.run(program, &check)?.success {
            break;
        }
        let mut delete = vec!["-w"];
        delete.extend(table);
        delete.extend(["-D", parent]);
        delete.extend(rule);
        run_checked(runner, program, &delete)?;
    }
    Ok(())
}

fn detect_linux_interface(runner: &mut dyn CommandRunner) -> Result<String> {
    let output = run_checked(runner, "ip", &["route", "show", "default"])?;
    output
        .stdout
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields
                .windows(2)
                .find(|pair| pair[0] == "dev")
                .map(|pair| pair[1].to_string())
        })
        .filter(|line| !line.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Could not detect default egress interface for TUN NAT"))
}

fn validate_interface(interface: &str) -> Result<()> {
    if interface.is_empty()
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        anyhow::bail!("Invalid network interface name: {interface:?}");
    }
    Ok(())
}

fn setup_freebsd_firewall(
    runner: &mut dyn CommandRunner,
    tun_interface: &str,
    subnet: &str,
    nat_enabled: bool,
    public_addresses: &[std::net::IpAddr],
    allow_c2c: bool,
    allowed_ranges: &[Cidr],
    anchor_path: &Path,
) -> Result<()> {
    validate_interface(tun_interface)?;
    let status = run_checked(runner, "pfctl", &["-s", "Running"])?;
    if !status.stdout.contains("Enabled") {
        anyhow::bail!(
            "PF is disabled; enable it with a main ruleset before starting TUN mode. rVPN will not enable PF or replace /etc/pf.conf"
        );
    }

    let forwarding = run_checked(runner, "sysctl", &["-n", "net.inet.ip.forwarding"])?;
    if forwarding.stdout.trim() != "1" {
        anyhow::bail!("net.inet.ip.forwarding is disabled; enable it before starting TUN mode");
    }

    let rules = run_checked(runner, "pfctl", &["-s", "rules"])?.stdout;
    if !has_pf_attachment(&rules, "anchor") {
        anyhow::bail!(
            "Active PF rules lack anchor \"rvpn\"; add anchor \"rvpn\" before broad quick passes and load the main ruleset before starting TUN mode"
        );
    }
    warn_if_earlier_quick_pass(&rules);

    let nat_rules = run_checked(runner, "pfctl", &["-s", "nat"])?.stdout;
    if !has_pf_attachment(&nat_rules, "nat-anchor") {
        anyhow::bail!(
            "Active PF NAT rules lack nat-anchor \"rvpn\"; add nat-anchor \"rvpn\" and load the main ruleset before starting TUN mode"
        );
    }

    let egress_interface = if nat_enabled {
        Some(detect_freebsd_interface(runner)?)
    } else {
        None
    };
    let rendered = render_pf_anchor(
        tun_interface,
        subnet,
        egress_interface.as_deref(),
        nat_enabled,
        public_addresses,
        allow_c2c,
        allowed_ranges,
    );
    validate_and_load_pf_anchor(runner, anchor_path, &rendered)
}

fn has_pf_attachment(rules: &str, kind: &str) -> bool {
    let prefix = format!("{kind} \"rvpn\"");
    rules
        .lines()
        .any(|line| line.trim_start().starts_with(&prefix))
}

fn warn_if_earlier_quick_pass(rules: &str) {
    for line in rules.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("anchor \"rvpn\"") {
            break;
        }
        if trimmed.starts_with("pass ") && trimmed.contains(" quick") {
            warn!(
                "PF has a pass quick rule before anchor \"rvpn\"; it can bypass TUN containment. Move the anchor before broad quick passes"
            );
        }
    }
}

fn detect_freebsd_interface(runner: &mut dyn CommandRunner) -> Result<String> {
    let output = run_checked(runner, "route", &["-n", "get", "default"])?;
    output
        .stdout
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("interface:")
                .map(|interface| interface.trim().to_string())
        })
        .filter(|interface| !interface.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Could not detect default egress interface for TUN NAT"))
}

fn render_pf_anchor(
    tun_interface: &str,
    subnet: &str,
    egress_interface: Option<&str>,
    nat_enabled: bool,
    public_addresses: &[std::net::IpAddr],
    allow_c2c: bool,
    allowed_ranges: &[Cidr],
) -> String {
    let mut rendered = format!("tun_if = \"{tun_interface}\"\ntun_net = \"{subnet}\"\n");
    if nat_enabled {
        rendered.push_str(&format!(
            "ext_if = \"{}\"\nnat on $ext_if from $tun_net to any -> ($ext_if)\n",
            egress_interface.expect("NAT requires an egress interface")
        ));
    }
    // PF evaluates `quick` rules first-match-wins, so every host block must
    // precede the exemptions and the broad pass. The interface's own
    // addresses (the TUN gateway included) are not in the special-use
    // ranges — block them explicitly so TUN clients cannot reach SSH or any
    // other service on the server itself.
    rendered.push_str("block in quick on $tun_if from any to (self)\n");
    // Configured public addresses (1:1 NAT) are not on any interface, so
    // (self) cannot see them — block each one explicitly.
    for address in public_addresses {
        rendered.push_str(&format!(
            "block in quick on $tun_if from any to {address}\n"
        ));
    }
    // C24 opt-in exemptions, before the special-use blocks so they match.
    // Client-to-client stays within the pool; listed ranges are exact CIDRs.
    if allow_c2c {
        rendered.push_str("pass in quick on $tun_if from $tun_net to $tun_net keep state\n");
    }
    for (network, prefix) in allowed_ranges {
        rendered.push_str(&format!(
            "pass in quick on $tun_if from any to {network}/{prefix} keep state\n"
        ));
    }
    for cidr in BLOCKED_IPV4_CIDRS.iter().chain(BLOCKED_IPV6_CIDRS) {
        rendered.push_str(&format!("block in quick on $tun_if from any to {cidr}\n"));
    }
    rendered.push_str(
        "pass in quick on $tun_if from $tun_net to any keep state\nblock in quick on $tun_if all\n",
    );
    rendered
}

fn validate_and_load_pf_anchor(
    runner: &mut dyn CommandRunner,
    anchor_path: &Path,
    rendered: &str,
) -> Result<()> {
    let parent = anchor_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("PF anchor path has no parent directory"))?;
    let temporary = temporary_anchor_path(anchor_path);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(rendered.as_bytes())?;
            file.sync_all()
        })
        .with_context(|| {
            format!(
                "Failed to write temporary PF anchor in {}",
                parent.display()
            )
        })?;

    let validation = run_checked(
        runner,
        "pfctl",
        &["-a", "rvpn", "-nf", &temporary.to_string_lossy()],
    );
    if let Err(error) = validation {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.context(
            "Generated PF anchor failed validation; existing anchor and main rules were not changed",
        ));
    }

    std::fs::rename(&temporary, anchor_path).with_context(|| {
        format!(
            "Failed to install validated PF anchor {}; existing main rules were not changed",
            anchor_path.display()
        )
    })?;
    run_checked(
        runner,
        "pfctl",
        &["-a", "rvpn", "-f", &anchor_path.to_string_lossy()],
    )
    .context("Failed to load PF anchor rvpn; main rules were not changed")?;
    Ok(())
}

fn temporary_anchor_path(anchor_path: &Path) -> PathBuf {
    let name = anchor_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("rvpn.anchor.conf");
    anchor_path.with_file_name(format!(".{name}.{}.tmp", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct FakeBinaries {
        _directory: tempfile::TempDir,
        root: PathBuf,
    }

    impl FakeBinaries {
        fn new(script: &str) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().to_path_buf();
            for name in ["iptables", "ip6tables", "pfctl", "ip", "route", "sysctl"] {
                let path = root.join(name);
                std::fs::write(&path, script).unwrap();
                let mut permissions = std::fs::metadata(&path).unwrap().permissions();
                permissions.set_mode(0o700);
                std::fs::set_permissions(path, permissions).unwrap();
            }
            Self {
                _directory: directory,
                root,
            }
        }

        fn path(&self, name: impl AsRef<str>) -> PathBuf {
            self.root.join(name.as_ref())
        }

        fn log(&self) -> String {
            std::fs::read_to_string(self.path("commands.log")).unwrap_or_default()
        }
    }

    impl CommandRunner for FakeBinaries {
        fn run(&mut self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
            let output = Command::new(self.path(program))
                .args(args)
                .current_dir(&self.root)
                .output()?;
            Ok(CommandOutput {
                success: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
    }

    const IPTABLES_FAKE: &str = r#"#!/bin/sh
set -eu
program=$(basename "$0")
{
  printf '%s' "$program"
  printf ' %s' "$@"
  printf '\n'
} >> commands.log
if [ "$program" = ip ]; then
  echo 'default via 192.0.2.1 dev eth0'
  exit 0
fi
args="$*"
case "$args" in
  *" -L "*)
    chain=${args##* }
    [ -f "$program.$chain.chain" ]
    ;;
  *" -N "*)
    chain=${args##* }
    if [ -f "$program.$chain.chain" ]; then exit 1; fi
    : > "$program.$chain.chain"
    ;;
  *" -F "*)
    chain=${args##* }
    case "$chain" in RVPN_*) [ -f "$program.$chain.chain" ] ;; *) exit 90 ;; esac
    ;;
  *" -C "*)
    key=${args#*-C }
    [ -f "$program.jumps" ] && grep -Fqx "$key" "$program.jumps"
    ;;
  *" -D "*)
    key=${args#*-D }
    grep -Fvx "$key" "$program.jumps" > "$program.jumps.new" || true
    mv "$program.jumps.new" "$program.jumps"
    ;;
  *" -I "*)
    key=${args#*-I }
    key=${key#* 1 }
    printf '%s\n' "$key" >> "$program.jumps"
    ;;
  *" -A "*)
    ;;
  *)
    exit 91
    ;;
esac
"#;

    #[test]
    fn linux_rules_are_owned_idempotent_and_fail_closed() {
        let mut fake = FakeBinaries::new(IPTABLES_FAKE);
        setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", true, &[], false, &[]).unwrap();
        setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", true, &[], false, &[]).unwrap();
        let log = fake.log();
        assert!(log.contains("iptables -w -A RVPN_FORWARD -i tun0 -d 100.64.0.0/10 -j DROP"));
        assert!(log.contains("ip6tables -w -A RVPN_FORWARD -i tun0 -d 64:ff9b::/96 -j DROP"));
        assert!(log.contains("iptables -w -t nat -A RVPN_NAT -s 10.200.0.0/24 -o"));
        assert!(log.contains("--ctstate ESTABLISHED,RELATED"));
        assert!(!log.contains("-F INPUT"));
        assert!(!log.contains("-F FORWARD"));
        assert!(!log.contains("-F POSTROUTING"));

        for program in ["iptables", "ip6tables"] {
            let jumps = std::fs::read_to_string(fake.path(format!("{program}.jumps"))).unwrap();
            let mut lines: Vec<&str> = jumps.lines().collect();
            lines.sort_unstable();
            lines.dedup();
            let expected = if program == "iptables" { 4 } else { 3 };
            assert_eq!(lines.len(), expected, "{program} jumps must not duplicate");
        }
    }

    #[test]
    fn nat_disabled_still_installs_containment_without_masquerade() {
        let mut fake = FakeBinaries::new(IPTABLES_FAKE);
        setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", false, &[], false, &[]).unwrap();
        let log = fake.log();
        assert!(log.contains("RVPN_INPUT -i tun0 -j DROP"));
        assert!(!log.contains("MASQUERADE"));
        assert!(!log.contains("ip route show default"));
    }

    #[test]
    fn linux_ipv6_from_tun_is_never_forwarded() {
        let mut fake = FakeBinaries::new(IPTABLES_FAKE);
        setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", true, &[], false, &[]).unwrap();
        let log = fake.log();
        // IPv4 is source-bound to the client pool; IPv6 has no pool yet, so
        // the ip6tables family must not contain any ACCEPT from the TUN
        // interface — only explicit CIDR drops and catch-all DROPs.
        assert!(log.contains("iptables -w -A RVPN_FORWARD -i tun0 -s 10.200.0.0/24 -j ACCEPT"));
        for line in log.lines() {
            if line.starts_with("ip6tables") && line.contains("RVPN_FORWARD -i tun0") {
                assert!(
                    line.contains("-j DROP"),
                    "ip6tables must not accept from the TUN interface: {line}"
                );
            }
        }
    }

    #[test]
    fn linux_drops_configured_public_addresses_per_family() {
        let mut fake = FakeBinaries::new(IPTABLES_FAKE);
        let public: &[std::net::IpAddr] = &[
            "8.8.8.8".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", true, public, false, &[]).unwrap();
        let log = fake.log();
        assert!(log.contains("iptables -w -A RVPN_FORWARD -i tun0 -d 8.8.8.8 -j DROP"));
        assert!(
            log.contains("ip6tables -w -A RVPN_FORWARD -i tun0 -d 2606:4700:4700::1111 -j DROP")
        );
        assert!(!log.contains("iptables -w -A RVPN_FORWARD -i tun0 -d 2606:4700:4700::1111"));
        assert!(!log.contains("ip6tables -w -A RVPN_FORWARD -i tun0 -d 8.8.8.8"));
    }

    #[test]
    fn linux_command_failure_aborts_setup() {
        let script = "#!/bin/sh\nprintf '%s %s\\n' \"$0\" \"$*\" >> commands.log\nexit 1\n";
        let mut fake = FakeBinaries::new(script);
        let error = setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", true, &[], false, &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("iptables"));
        assert!(!fake.log().contains("MASQUERADE"));
    }

    const PF_FAKE: &str = r#"#!/bin/sh
set -eu
program=$(basename "$0")
{
  printf '%s' "$program"
  printf ' %s' "$@"
  printf '\n'
} >> commands.log
case "$program $*" in
  "pfctl -s Running")
    if [ -f pf-disabled ]; then echo 'Status: Disabled'; else echo 'Status: Enabled'; fi
    ;;
  "pfctl -s rules")
    if [ -f main-rules ]; then cat main-rules; else printf 'anchor "rvpn" all\n'; fi
    ;;
  "pfctl -s nat")
    if [ -f main-nat ]; then cat main-nat; else printf 'nat-anchor "rvpn" all\n'; fi
    ;;
  "sysctl -n net.inet.ip.forwarding")
    if [ -f forwarding-disabled ]; then echo 0; else echo 1; fi
    ;;
  "route -n get default")
    echo '   interface: vtnet0'
    ;;
  "pfctl -a rvpn -nf "*)
    if [ -f syntax-error ]; then echo 'invalid anchor' >&2; exit 1; fi
    ;;
  "pfctl -a rvpn -f "*)
    if [ -f load-error ]; then echo 'load failed' >&2; exit 1; fi
    cp "$4" anchor-loaded
    ;;
  *)
    echo "unsafe or unexpected command: $program $*" >&2
    exit 92
    ;;
esac
"#;

    fn pf_test() -> (FakeBinaries, tempfile::TempDir, PathBuf) {
        let fake = FakeBinaries::new(PF_FAKE);
        let directory = tempfile::tempdir().unwrap();
        let anchor = directory.path().join("rvpn.anchor.conf");
        (fake, directory, anchor)
    }

    #[test]
    fn freebsd_validates_and_loads_only_rvpn_anchor() {
        let (mut fake, _directory, anchor) = pf_test();
        setup_freebsd_firewall(
            &mut fake,
            "tun0",
            "10.200.0.0/24",
            true,
            &[],
            false,
            &[],
            &anchor,
        )
        .unwrap();
        let log = fake.log();
        assert!(log.contains("pfctl -a rvpn -nf"));
        assert!(log.contains("pfctl -a rvpn -f"));
        assert!(!log.lines().any(|line| line.starts_with("pfctl -f")));
        assert!(!log.contains("pfctl -F"));
        let rendered = std::fs::read_to_string(anchor).unwrap();
        assert!(rendered.contains("nat on $ext_if from $tun_net to any -> ($ext_if)"));
        assert!(rendered.contains("ext_if = \"vtnet0\""));
        assert!(rendered.contains("block in quick on $tun_if from any to 100.64.0.0/10"));
        assert!(rendered.contains("block in quick on $tun_if from any to 64:ff9b::/96"));
        let self_block = rendered
            .find("block in quick on $tun_if from any to (self)")
            .expect("anchor must block the host's own interface addresses");
        let pass = rendered.find("pass in quick on $tun_if").unwrap();
        assert!(
            self_block < pass,
            "(self) block must precede the broad pass"
        );
        assert!(rendered.ends_with("block in quick on $tun_if all\n"));
        assert_eq!(
            std::fs::read_to_string(fake.path("anchor-loaded")).unwrap(),
            rendered
        );
    }

    #[test]
    fn freebsd_blocks_configured_public_addresses_before_the_pass() {
        let (mut fake, _directory, anchor) = pf_test();
        let public: &[std::net::IpAddr] = &[
            "8.8.8.8".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        setup_freebsd_firewall(
            &mut fake,
            "tun0",
            "10.200.0.0/24",
            true,
            public,
            false,
            &[],
            &anchor,
        )
        .unwrap();
        let rendered = std::fs::read_to_string(anchor).unwrap();
        let public_block = rendered
            .find("block in quick on $tun_if from any to 8.8.8.8")
            .expect("anchor must block configured public addresses");
        let v6_block = rendered
            .find("block in quick on $tun_if from any to 2606:4700:4700::1111")
            .expect("anchor must block configured public IPv6 addresses");
        let pass = rendered.find("pass in quick on $tun_if").unwrap();
        assert!(
            public_block < pass,
            "configured block must precede the pass"
        );
        assert!(v6_block < pass, "configured v6 block must precede the pass");
    }

    #[test]
    fn freebsd_prerequisites_fail_before_anchor_changes() {
        for marker in ["pf-disabled", "forwarding-disabled"] {
            let (mut fake, _directory, anchor) = pf_test();
            std::fs::write(fake.path(marker), "").unwrap();
            setup_freebsd_firewall(
                &mut fake,
                "tun0",
                "10.200.0.0/24",
                true,
                &[],
                false,
                &[],
                &anchor,
            )
            .unwrap_err();
            assert!(!anchor.exists());
            assert!(!fake.log().contains(" -f "));
        }

        let (mut fake, _directory, anchor) = pf_test();
        std::fs::write(fake.path("main-rules"), "pass all\n").unwrap();
        let error = setup_freebsd_firewall(
            &mut fake,
            "tun0",
            "10.200.0.0/24",
            true,
            &[],
            false,
            &[],
            &anchor,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("anchor \"rvpn\""));
        assert!(!anchor.exists());

        let (mut fake, _directory, anchor) = pf_test();
        std::fs::write(
            fake.path("main-nat"),
            "nat on vtnet0 from any to any -> (vtnet0)\n",
        )
        .unwrap();
        setup_freebsd_firewall(
            &mut fake,
            "tun0",
            "10.200.0.0/24",
            true,
            &[],
            false,
            &[],
            &anchor,
        )
        .unwrap_err();
        assert!(!anchor.exists());
    }

    #[test]
    fn freebsd_syntax_and_load_failures_do_not_touch_main_rules() {
        for marker in ["syntax-error", "load-error"] {
            let (mut fake, _directory, anchor) = pf_test();
            std::fs::write(fake.path("main-rules"), "anchor \"rvpn\" all\n").unwrap();
            std::fs::write(fake.path(marker), "").unwrap();
            setup_freebsd_firewall(
                &mut fake,
                "tun0",
                "10.200.0.0/24",
                true,
                &[],
                false,
                &[],
                &anchor,
            )
            .unwrap_err();
            assert_eq!(
                std::fs::read_to_string(fake.path("main-rules")).unwrap(),
                "anchor \"rvpn\" all\n"
            );
            assert!(!fake.path("anchor-loaded").exists());
            assert!(!fake.log().lines().any(|line| line.starts_with("pfctl -f")));
        }
    }

    #[test]
    fn freebsd_nat_false_still_requires_anchors_and_containment() {
        let (mut fake, _directory, anchor) = pf_test();
        setup_freebsd_firewall(
            &mut fake,
            "tun0",
            "10.200.0.0/24",
            false,
            &[],
            false,
            &[],
            &anchor,
        )
        .unwrap();
        let rendered = std::fs::read_to_string(anchor).unwrap();
        assert!(!rendered.contains("nat on"));
        assert!(rendered.contains("pass in quick"));
        assert!(!fake.log().contains("route -n get default"));
    }

    // ---- C24: opt-in client egress exemptions (task #rVPN:#18) ----

    #[test]
    fn linux_c2c_accept_precedes_special_use_drops() {
        let mut fake = FakeBinaries::new(IPTABLES_FAKE);
        setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", true, &[], true, &[]).unwrap();
        let log = fake.log();
        let accept = log
            .find("iptables -w -A RVPN_FORWARD -i tun0 -o tun0 -s 10.200.0.0/24 -d 10.200.0.0/24 -j ACCEPT")
            .expect("client-to-client ACCEPT must exist when the flag is on");
        let drop_10 = log
            .find("iptables -w -A RVPN_FORWARD -i tun0 -d 10.0.0.0/8 -j DROP")
            .expect("10/8 drop must still exist");
        assert!(
            accept < drop_10,
            "exemption must match before the CIDR drop"
        );
        // The pool is IPv4: the v6 family gets no client-to-client rule.
        assert!(!log.contains("ip6tables -w -A RVPN_FORWARD -i tun0 -o tun0"));
    }

    #[test]
    fn linux_flag_off_adds_no_exemption_rules() {
        let mut fake = FakeBinaries::new(IPTABLES_FAKE);
        setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", true, &[], false, &[]).unwrap();
        let log = fake.log();
        assert!(!log.contains("-o tun0 -s 10.200.0.0/24 -d 10.200.0.0/24 -j ACCEPT"));
        // Containment unchanged: every special-use drop still present.
        assert!(log.contains("iptables -w -A RVPN_FORWARD -i tun0 -d 10.0.0.0/8 -j DROP"));
        assert!(log.contains("iptables -w -A RVPN_FORWARD -i tun0 -d 192.168.0.0/16 -j DROP"));
    }

    #[test]
    fn linux_allowed_range_accepts_precede_drops_per_family() {
        let mut fake = FakeBinaries::new(IPTABLES_FAKE);
        let ranges = vec![
            egress::parse_cidr("192.168.1.0/24").unwrap(),
            egress::parse_cidr("2001:db8::/32").unwrap(),
        ];
        setup_linux_firewall(
            &mut fake,
            "tun0",
            "10.200.0.0/24",
            true,
            &[],
            false,
            &ranges,
        )
        .unwrap();
        let log = fake.log();
        let v4_accept = log
            .find("iptables -w -A RVPN_FORWARD -i tun0 -d 192.168.1.0/24 -j ACCEPT")
            .expect("listed v4 range ACCEPT");
        let v4_drop = log
            .find("iptables -w -A RVPN_FORWARD -i tun0 -d 192.168.0.0/16 -j DROP")
            .expect("192.168/16 drop");
        assert!(v4_accept < v4_drop);
        let v6_accept = log
            .find("ip6tables -w -A RVPN_FORWARD -i tun0 -d 2001:db8::/32 -j ACCEPT")
            .expect("listed v6 range ACCEPT in the v6 family");
        let v6_drop = log
            .find("ip6tables -w -A RVPN_FORWARD -i tun0 -d 2001:db8::/32 -j DROP")
            .expect("documentation-range drop");
        assert!(v6_accept < v6_drop);
        // Unlisted neighbours stay dropped.
        assert!(!log.contains("-d 192.168.2.0/24 -j ACCEPT"));
    }

    #[test]
    fn linux_public_address_drops_precede_exemptions() {
        let mut fake = FakeBinaries::new(IPTABLES_FAKE);
        let public: Vec<std::net::IpAddr> = vec!["203.0.113.5".parse().unwrap()];
        setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", true, &public, true, &[]).unwrap();
        let log = fake.log();
        let host_drop = log
            .find("iptables -w -A RVPN_FORWARD -i tun0 -d 203.0.113.5 -j DROP")
            .expect("configured public address drop");
        let c2c = log
            .find("-i tun0 -o tun0 -s 10.200.0.0/24 -d 10.200.0.0/24 -j ACCEPT")
            .expect("c2c accept");
        assert!(host_drop < c2c, "host denial must win over exemptions");
    }

    #[test]
    fn linux_downlink_accepts_only_established_replies_even_with_c2c_on() {
        // A13 per-direction assertion: unsolicited NEW from the segment
        // toward a tunnel client must drop by chain order. The only ACCEPT
        // toward tun0 is the conntrack reply rule (scoped to the pool), the
        // catch-all drop sits after it, and no rule accepts NEW inbound —
        // with the client-to-client flag ON as well, since the exemption is
        // tun->tun only and must never become segment->tun port forwarding.
        let mut fake = FakeBinaries::new(IPTABLES_FAKE);
        setup_linux_firewall(&mut fake, "tun0", "10.200.0.0/24", true, &[], true, &[]).unwrap();
        let log = fake.log();
        let reply = log
            .find("iptables -w -A RVPN_FORWARD -o tun0 -m conntrack --ctstate ESTABLISHED,RELATED -d 10.200.0.0/24 -j ACCEPT")
            .expect("conntrack reply accept");
        let catch_all = log
            .find("iptables -w -A RVPN_FORWARD -o tun0 -j DROP")
            .expect("inbound catch-all drop");
        assert!(reply < catch_all);
        assert!(!log.contains("iptables -w -A RVPN_FORWARD -o tun0 -j ACCEPT"));
        // No exemption rule may carry a non-tun input interface.
        for line in log.lines().filter(|line| line.contains("-j ACCEPT")) {
            if line.contains("-o tun0") {
                assert!(
                    line.contains("-i tun0") || line.contains("conntrack"),
                    "inbound ACCEPT without conntrack or tun source: {line}"
                );
            }
        }
    }

    #[test]
    fn pf_exemptions_sit_between_host_blocks_and_special_use_blocks() {
        let ranges = vec![egress::parse_cidr("192.168.1.0/24").unwrap()];
        let public: Vec<std::net::IpAddr> = vec!["203.0.113.5".parse().unwrap()];
        let rules = render_pf_anchor(
            "tun0",
            "10.200.0.0/24",
            Some("vtnet0"),
            true,
            &public,
            true,
            &ranges,
        );
        let self_block = rules.find("to (self)").expect("(self) block");
        let public_block = rules.find("to 203.0.113.5").expect("public block");
        let c2c = rules.find("from $tun_net to $tun_net").expect("c2c pass");
        let listed = rules.find("to 192.168.1.0/24").expect("listed pass");
        let special = rules.find("to 192.168.0.0/16").expect("special-use block");
        let broad = rules
            .find("pass in quick on $tun_if from $tun_net to any keep state")
            .expect("broad pass");
        assert!(self_block < c2c, "host block before exemptions");
        assert!(public_block < c2c, "public block before exemptions");
        assert!(
            c2c < special && listed < special,
            "exemptions before special-use blocks"
        );
        assert!(special < broad, "special-use blocks before the broad pass");
    }

    #[test]
    fn pf_flag_off_and_empty_list_keep_the_strict_anchor() {
        let rules = render_pf_anchor(
            "tun0",
            "10.200.0.0/24",
            Some("vtnet0"),
            true,
            &[],
            false,
            &[],
        );
        assert!(!rules.contains("to $tun_net keep state"));
        assert!(!rules.contains("192.168.1.0/24"));
        assert!(rules.contains("block in quick on $tun_if from any to 192.168.0.0/16"));
        assert!(rules.contains("pass in quick on $tun_if from $tun_net to any keep state"));
    }
}
