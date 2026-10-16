//! The open-file limit.
//!
//! systemd starts services with a soft limit of 1024 under a much higher hard
//! one, and expects a process that needs more to raise it itself — which Bun
//! and Node do on startup, and Rust does not. A Rust boot with a socket per
//! relay per bridge hit EMFILE at about 250 bridges, failing the other 1100
//! starts and the CA-store reads under them (2026-10-16). Connections are per
//! community now (~450 descriptors for 1340 bridges), but one community's
//! worth of relays, a burst of Discord REST, or the next design should not
//! meet a limit chosen for interactive shells. Every binary calls [`raise`]
//! before opening anything.

/// Raise the soft limit to the hard limit; returns the new soft limit.
#[cfg(unix)]
pub fn raise() -> std::io::Result<u64> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit/setrlimit only read and write the struct we pass.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if lim.rlim_cur < lim.rlim_max {
        lim.rlim_cur = lim.rlim_max;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(lim.rlim_cur)
}

#[cfg(not(unix))]
pub fn raise() -> std::io::Result<u64> {
    Ok(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn raises_the_soft_limit_to_the_hard_one() {
        let soft = super::raise().unwrap();
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        assert_eq!(soft, lim.rlim_max);
        assert_eq!(lim.rlim_cur, lim.rlim_max);
    }
}
