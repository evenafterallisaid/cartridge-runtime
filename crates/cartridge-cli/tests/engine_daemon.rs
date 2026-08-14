use std::{
    fs,
    io::Write,
    net::TcpStream,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use cartridge_engine::DaemonEndpoint;

const WAIT_LIMIT: Duration = Duration::from_secs(15);

struct DaemonGuard(Option<Child>);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn daemon_authenticates_clients_survives_bad_frames_and_cleans_up() {
    let directory = tempfile::tempdir().unwrap();
    let engine = directory.path().join("engine");
    let library = directory.path().join("library");
    fs::create_dir(&library).unwrap();
    let binary = env!("CARGO_BIN_EXE_cartridge");
    let child = Command::new(binary)
        .args([
            "engine",
            "serve",
            "--root",
            engine.to_str().unwrap(),
            "--library",
            library.to_str().unwrap(),
            "--max-supervisors",
            "2",
            "--workers-per-stack",
            "4",
            "--json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut daemon = DaemonGuard(Some(child));
    let endpoint_path = engine.join("daemon.json");
    wait_until(|| endpoint_path.exists());
    let endpoint = DaemonEndpoint::read(&engine).unwrap();

    let mut unauthenticated = TcpStream::connect(("127.0.0.1", endpoint.port)).unwrap();
    unauthenticated.write_all(&1_u32.to_be_bytes()).unwrap();
    unauthenticated.write_all(b"x").unwrap();
    drop(unauthenticated);

    let ping = run(
        binary,
        &[
            "engine",
            "ping",
            "--root",
            engine.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(
        ping.status.success(),
        "{}",
        String::from_utf8_lossy(&ping.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&ping.stdout).trim(),
        "{\"reachable\":true}"
    );

    let info = run(
        binary,
        &[
            "engine",
            "info",
            "--root",
            engine.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info["instance_id"], endpoint.instance_id);
    assert_eq!(info["max_supervisors"], 2);
    assert_eq!(info["workers_per_stack"], 4);

    let shutdown = run(
        binary,
        &[
            "engine",
            "shutdown",
            "--root",
            engine.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(shutdown.status.success());
    wait_until(|| daemon.0.as_mut().unwrap().try_wait().unwrap().is_some());
    let output = daemon.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("key_hex"));
    assert!(!endpoint_path.exists());
}

fn run(binary: &str, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT_LIMIT;
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the daemon"
        );
        thread::sleep(Duration::from_millis(25));
    }
}
