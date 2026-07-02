use std::{fs, path::PathBuf};

use akamu_client::RenewalConfig;

use crate::args::InstallTimerArgs;

// ── install timer ─────────────────────────────────────────────────────────────

pub(crate) fn cmd_install_timer(args: InstallTimerArgs) -> Result<(), String> {
    let toml_str = fs::read_to_string(&args.renewal_config)
        .map_err(|e| format!("read {}: {e}", args.renewal_config.display()))?;
    let cfg: RenewalConfig = toml::from_str(&toml_str)
        .map_err(|e| format!("parse {}: {e}", args.renewal_config.display()))?;

    let first_domain = cfg
        .domains
        .first()
        .ok_or("renewal config has no domains")?
        .value
        .clone();

    let unit_base = args.unit_name.unwrap_or_else(|| {
        let sanitized = first_domain
            .strip_prefix("*.")
            .map(|rest| format!("wildcard-{rest}"))
            .unwrap_or_else(|| first_domain.clone());
        format!("akamu-renew-{sanitized}")
    });

    let config_path = args
        .renewal_config
        .canonicalize()
        .unwrap_or_else(|_| args.renewal_config.clone());

    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "akamu-cli".to_string());

    let service_name = format!("{unit_base}.service");
    let timer_name = format!("{unit_base}.timer");

    let service_content = format!(
        "[Unit]\n\
         Description=Renew ACME certificate for {first_domain}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={exe} renew --renewal-config {config_path}\n",
        config_path = config_path.display(),
    );

    let timer_content = format!(
        "[Unit]\n\
         Description=Daily ACME certificate renewal for {first_domain}\n\
         \n\
         [Timer]\n\
         OnCalendar={on_calendar}\n\
         RandomizedDelaySec=1h\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n",
        on_calendar = args.on_calendar,
    );

    if args.print_only {
        println!("# --- {service_name} ---");
        print!("{service_content}");
        println!("# --- {timer_name} ---");
        print!("{timer_content}");
        return Ok(());
    }

    let user_mode = if args.user {
        true
    } else if args.system {
        false
    } else {
        effective_uid() != 0
    };

    let unit_dir = if user_mode {
        let cfg_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/root"));
                home.join(".config")
            });
        cfg_home.join("systemd/user")
    } else {
        PathBuf::from("/etc/systemd/system")
    };

    fs::create_dir_all(&unit_dir).map_err(|e| format!("create {}: {e}", unit_dir.display()))?;

    let service_path = unit_dir.join(&service_name);
    let timer_path = unit_dir.join(&timer_name);

    if !args.force {
        for p in [&service_path, &timer_path] {
            if p.exists() {
                return Err(format!(
                    "{} already exists; use --force to overwrite",
                    p.display()
                ));
            }
        }
    }

    fs::write(&service_path, service_content.as_bytes())
        .map_err(|e| format!("write {}: {e}", service_path.display()))?;
    fs::write(&timer_path, timer_content.as_bytes())
        .map_err(|e| format!("write {}: {e}", timer_path.display()))?;
    println!("Written: {}", service_path.display());
    println!("Written: {}", timer_path.display());

    let sc_user_flag: &[&str] = if user_mode { &["--user"] } else { &[] };

    let run_systemctl = |extra: &[&str]| -> Result<(), String> {
        let status = std::process::Command::new("systemctl")
            .args(sc_user_flag)
            .args(extra)
            .status()
            .map_err(|e| format!("systemctl: {e}"))?;
        if !status.success() {
            return Err(format!("systemctl {} failed: {status}", extra.join(" ")));
        }
        Ok(())
    };

    run_systemctl(&["daemon-reload"])?;

    let do_enable = args.enable || args.now;
    if do_enable {
        run_systemctl(&["enable", &timer_name])?;
        println!("Enabled: {timer_name}");
    }
    if args.now {
        run_systemctl(&["start", &timer_name])?;
        println!("Started: {timer_name}");
    }

    if !do_enable {
        let sc = if user_mode {
            "systemctl --user"
        } else {
            "systemctl"
        };
        println!("\nTo enable automatic renewal:");
        println!("  {sc} enable --now {timer_name}");
    }

    Ok(())
}

/// Return the effective UID of the current process.
/// Reads /proc/self/status on Linux; returns 0 on any parse failure so that
/// the caller defaults to system-mode installation in ambiguous cases.
fn effective_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        let Ok(status) = fs::read_to_string("/proc/self/status") else {
            eprintln!(
                "Warning: cannot read /proc/self/status; defaulting to system-mode installation"
            );
            return 0;
        };
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                // Fields: real effective saved fs — index 1 is effective UID.
                if let Some(euid) = rest.split_whitespace().nth(1).and_then(|s| s.parse().ok()) {
                    return euid;
                }
            }
        }
        eprintln!("Warning: cannot determine effective UID from /proc/self/status; defaulting to system-mode installation");
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}
