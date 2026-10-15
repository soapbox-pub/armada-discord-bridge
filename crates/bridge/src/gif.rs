//! mp4 -> gif transcode via the system ffmpeg, for GIF-picker providers that
//! publish no real .gif asset (Klipy's embeds carry only mp4 + webp). Small
//! clips only; 15 fps capped at 320px wide keeps output sizes tolerable.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// Wall-clock ceiling on one transcode. The input is an mp4 named by a remote
/// page's OpenGraph tags, so its duration and complexity are attacker-chosen;
/// without this a single message pins a core indefinitely.
const FFMPEG_TIMEOUT: Duration = Duration::from_secs(20);

/// Seconds of source honored. A GIF at 15fps and 320px wide runs to hundreds of
/// megabytes for a clip of any real length, and the size was only ever checked
/// after the file had been written to /tmp and read back into memory — so the
/// bound has to be on what ffmpeg is asked to produce, not on what it produced.
const FFMPEG_MAX_SECONDS: u32 = 10;

/// Hard ceiling handed to ffmpeg's `-fs`, so it stops writing rather than
/// filling /tmp. Mirrors the router's MAX_BLOB_BYTES (Discord's webhook upload
/// limit); duplicated rather than imported because the router imports this
/// module. The caller re-checks the returned length against its own limit.
const MAX_GIF_BYTES: u64 = 10 * 1024 * 1024;

/// Tail of ffmpeg's stderr kept for the error message. It is read to the end
/// regardless — a full pipe would stall ffmpeg until the timeout — but only
/// this much is held.
const STDERR_TAIL_BYTES: usize = 4096;

static FFMPEG: OnceLock<Option<PathBuf>> = OnceLock::new();

fn ffmpeg_path() -> Option<&'static Path> {
    FFMPEG.get_or_init(|| which("ffmpeg")).as_deref()
}

pub fn ffmpeg_available() -> bool {
    ffmpeg_path().is_some()
}

fn which(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

/// Removes the scratch directory on every exit, including a cancelled future.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub async fn mp4_to_gif(data: &[u8]) -> Result<Vec<u8>> {
    let ffmpeg = ffmpeg_path().ok_or_else(|| anyhow!("ffmpeg not installed"))?;
    let dir = TempDir(std::env::temp_dir().join(format!("bridge-gif-{}", hex::encode(rand::random::<[u8; 8]>()))));
    // Private and must not already exist, as mkdtemp guarantees.
    tokio::fs::DirBuilder::new().mode(0o700).create(&dir.0).await.context("creating transcode dir")?;
    let src = dir.0.join("in.mp4");
    let out = dir.0.join("out.gif");
    tokio::fs::write(&src, data).await?;

    let mut child = Command::new(ffmpeg)
        .arg("-y")
        .arg("-t")
        .arg(FFMPEG_MAX_SECONDS.to_string())
        .arg("-i")
        .arg(&src)
        .arg("-vf")
        .arg("fps=15,scale='min(320,iw)':-2:flags=lanczos")
        .arg("-fs")
        .arg(MAX_GIF_BYTES.to_string())
        .arg("-loop")
        .arg("0")
        .arg(&out)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        // A dropped future must not leave ffmpeg running unbounded.
        .kill_on_drop(true)
        .spawn()
        .context("spawning ffmpeg")?;

    let mut stderr = child.stderr.take().expect("stderr is piped");
    let run = async {
        let mut tail = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    tail.extend_from_slice(&buf[..n]);
                    if tail.len() > STDERR_TAIL_BYTES {
                        tail.drain(..tail.len() - STDERR_TAIL_BYTES);
                    }
                }
            }
        }
        (child.wait().await, tail)
    };
    let (status, tail) = match tokio::time::timeout(FFMPEG_TIMEOUT, run).await {
        Ok(done) => done,
        Err(_) => {
            let _ = child.kill().await;
            bail!("ffmpeg failed: timed out after {}s", FFMPEG_TIMEOUT.as_secs())
        }
    };
    if !status?.success() {
        bail!("ffmpeg failed: {}", String::from_utf8_lossy(&tail));
    }
    Ok(tokio::fs::read(&out).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transcodes_an_mp4() {
        let Some(ffmpeg) = ffmpeg_path() else { return };
        let dir = TempDir(std::env::temp_dir().join(format!("bridge-gif-test-{}", hex::encode(rand::random::<[u8; 8]>()))));
        std::fs::create_dir(&dir.0).unwrap();
        let mp4 = dir.0.join("src.mp4");
        let made = Command::new(ffmpeg)
            .args(["-loglevel", "error", "-f", "lavfi", "-i", "testsrc=duration=1:size=64x64:rate=5", "-pix_fmt", "yuv420p"])
            .arg(&mp4)
            .status()
            .await
            .unwrap();
        assert!(made.success());

        let gif = mp4_to_gif(&std::fs::read(&mp4).unwrap()).await.unwrap();
        assert!(gif.starts_with(b"GIF8"));
    }

    #[tokio::test]
    async fn rejects_garbage() {
        if !ffmpeg_available() {
            return;
        }
        let err = mp4_to_gif(b"not an mp4").await.unwrap_err();
        assert!(err.to_string().starts_with("ffmpeg failed"), "{err}");
    }
}
