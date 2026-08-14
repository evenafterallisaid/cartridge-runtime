use std::{
    ffi::{OsStr, OsString},
    io::{self, Read},
    process::ExitStatus,
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use command_group::{CommandGroup, GroupChild};
#[cfg(windows)]
use windows_spawn::{
    Child as WindowsChild, Command as WindowsCommand, DropPolicy, SpawnOptions,
    Stdio as WindowsStdio,
};

const PARENT_LIVENESS_ENV: &str = "CARTRIDGE_PARENT_LIVENESS";
const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub(crate) const TERMINATION_GRACE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
pub(crate) enum OutputMode {
    Inherit,
    Null,
}

pub(crate) struct ContainedCommand {
    program: OsString,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    stdout: OutputMode,
    stderr: OutputMode,
}

impl ContainedCommand {
    pub(crate) fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: program.as_ref().to_owned(),
            arguments: Vec::new(),
            environment: Vec::new(),
            stdout: OutputMode::Null,
            stderr: OutputMode::Null,
        }
    }

    pub(crate) fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        self.arguments.push(argument.as_ref().to_owned());
        self
    }

    pub(crate) fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.arguments
            .extend(arguments.into_iter().map(|value| value.as_ref().to_owned()));
        self
    }

    pub(crate) fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.environment
            .push((key.as_ref().to_owned(), value.as_ref().to_owned()));
        self
    }

    pub(crate) fn stdout(&mut self, mode: OutputMode) -> &mut Self {
        self.stdout = mode;
        self
    }

    pub(crate) fn stderr(&mut self, mode: OutputMode) -> &mut Self {
        self.stderr = mode;
        self
    }
}

pub(crate) struct ContainedChild {
    #[cfg(unix)]
    child: GroupChild,
    #[cfg(windows)]
    child: Option<WindowsChild>,
    running: bool,
    exit_status: Option<ExitStatus>,
}

impl ContainedChild {
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.exit_status.is_some() {
            return Ok(self.exit_status);
        }
        #[cfg(unix)]
        let status = self.child.try_wait()?;
        #[cfg(windows)]
        let status = self
            .child
            .as_mut()
            .expect("running child retains its handle")
            .try_wait()?;
        if status.is_some() {
            self.running = false;
            self.exit_status = status;
            #[cfg(windows)]
            drop(self.child.take());
        }
        Ok(status)
    }

    pub(crate) fn terminate(&mut self, grace: Duration) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.try_wait()? {
            return Ok(Some(status));
        }
        if let Err(error) = self.start_kill()
            && error.kind() != io::ErrorKind::InvalidInput
        {
            return Err(error);
        }
        let deadline = Instant::now() + grace;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                #[cfg(windows)]
                {
                    drop(self.child.take());
                    self.running = false;
                }
                return Ok(None);
            }
            thread::sleep(TERMINATION_POLL_INTERVAL);
        }
    }

    fn start_kill(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        return self.child.kill();
        #[cfg(windows)]
        return self
            .child
            .as_mut()
            .expect("running child retains its handle")
            .kill();
    }

    #[cfg(test)]
    fn disconnect_parent_for_test(&mut self) {
        #[cfg(unix)]
        drop(self.child.inner().stdin.take());
        #[cfg(windows)]
        drop(
            self.child
                .as_mut()
                .expect("running child retains its handle")
                .stdin
                .take(),
        );
    }
}

impl Drop for ContainedChild {
    fn drop(&mut self) {
        if self.running {
            #[cfg(unix)]
            let _ = self.child.kill();
            #[cfg(windows)]
            drop(self.child.take());
        }
    }
}

pub(crate) fn spawn_contained(
    command: &mut ContainedCommand,
    monitor_parent: bool,
) -> io::Result<ContainedChild> {
    if monitor_parent {
        command.env(PARENT_LIVENESS_ENV, "1");
    }

    #[cfg(unix)]
    let child = {
        let mut native = std::process::Command::new(&command.program);
        native
            .args(&command.arguments)
            .env_clear()
            .envs(command.environment.iter().cloned())
            .stdin(if monitor_parent {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(unix_stdio(command.stdout))
            .stderr(unix_stdio(command.stderr));
        native.group_spawn()?
    };
    #[cfg(windows)]
    let child = {
        let mut native = WindowsCommand::new(&command.program);
        native
            .args(&command.arguments)
            .env_clear()
            .envs(command.environment.iter().cloned())
            .stdin(if monitor_parent {
                WindowsStdio::piped()
            } else {
                WindowsStdio::null()
            })
            .stdout(windows_stdio(command.stdout))
            .stderr(windows_stdio(command.stderr));
        native.spawn_with(SpawnOptions::new().drop_policy(DropPolicy::KillTree))?
    };

    Ok(ContainedChild {
        #[cfg(unix)]
        child,
        #[cfg(windows)]
        child: Some(child),
        running: true,
        exit_status: None,
    })
}

#[cfg(unix)]
fn unix_stdio(mode: OutputMode) -> std::process::Stdio {
    match mode {
        OutputMode::Inherit => std::process::Stdio::inherit(),
        OutputMode::Null => std::process::Stdio::null(),
    }
}

#[cfg(windows)]
fn windows_stdio(mode: OutputMode) -> WindowsStdio {
    match mode {
        OutputMode::Inherit => WindowsStdio::inherit(),
        OutputMode::Null => WindowsStdio::null(),
    }
}

pub(crate) fn install_parent_liveness_watchdog() -> io::Result<()> {
    if std::env::var_os(PARENT_LIVENESS_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "worker has no parent-liveness channel",
        ));
    }
    thread::Builder::new()
        .name("parent-liveness".into())
        .spawn(|| {
            let mut input = io::stdin().lock();
            let mut byte = [0_u8; 1];
            loop {
                match input.read(&mut byte) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Ok(_) | Err(_) => std::process::exit(70),
                }
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Stdio};

    use super::*;

    const FIXTURE_ENV: &str = "CARTRIDGE_PROCESS_FIXTURE";
    const READY_ENV: &str = "CARTRIDGE_PROCESS_READY";
    const SENTINEL_ENV: &str = "CARTRIDGE_PROCESS_SENTINEL";

    #[test]
    fn contained_child_fixture() {
        let Some(mode) = std::env::var_os(FIXTURE_ENV) else {
            return;
        };
        let ready = std::env::var_os(READY_ENV).map(std::path::PathBuf::from);
        match mode.to_string_lossy().as_ref() {
            "liveness" => {
                install_parent_liveness_watchdog().unwrap();
                fs::write(ready.unwrap(), b"ready").unwrap();
                thread::sleep(Duration::from_secs(30));
            }
            "leader" => {
                let mut descendant = std::process::Command::new(std::env::current_exe().unwrap());
                let mut descendant = descendant
                    .args([
                        "--exact",
                        "process_control::tests::contained_child_fixture",
                        "--nocapture",
                    ])
                    .env(FIXTURE_ENV, "descendant")
                    .env(SENTINEL_ENV, std::env::var_os(SENTINEL_ENV).unwrap())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                fs::write(ready.unwrap(), b"ready").unwrap();
                thread::sleep(Duration::from_secs(30));
                let _ = descendant.kill();
                let _ = descendant.wait();
            }
            "cascade" => {
                install_parent_liveness_watchdog().unwrap();
                let ready = ready.unwrap();
                let child_ready = ready.with_extension("child-ready");
                let mut command = fixture_command("liveness-sentinel", &child_ready);
                command.env(SENTINEL_ENV, std::env::var_os(SENTINEL_ENV).unwrap());
                let _child = spawn_contained(&mut command, true).unwrap();
                wait_for_path(&child_ready);
                fs::write(ready, b"ready").unwrap();
                thread::sleep(Duration::from_secs(30));
            }
            "liveness-sentinel" => {
                install_parent_liveness_watchdog().unwrap();
                fs::write(ready.unwrap(), b"ready").unwrap();
                thread::sleep(Duration::from_secs(2));
                fs::write(std::env::var_os(SENTINEL_ENV).unwrap(), b"escaped").unwrap();
            }
            "descendant" => {
                thread::sleep(Duration::from_secs(2));
                fs::write(std::env::var_os(SENTINEL_ENV).unwrap(), b"escaped").unwrap();
            }
            value => panic!("unknown process fixture mode: {value}"),
        }
    }

    #[test]
    fn liveness_pipe_terminates_worker_when_parent_disconnects() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let mut command = fixture_command("liveness", &ready);
        let mut child = spawn_contained(&mut command, true).unwrap();
        wait_for_path(&ready);

        child.disconnect_parent_for_test();
        let status = wait_for_exit(&mut child);
        assert!(!status.success());
    }

    #[test]
    fn termination_kills_the_entire_descendant_tree() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let sentinel = directory.path().join("escaped");
        let mut command = fixture_command("leader", &ready);
        command.env(SENTINEL_ENV, &sentinel);
        let mut child = spawn_contained(&mut command, false).unwrap();
        wait_for_path(&ready);

        assert!(child.terminate(TERMINATION_GRACE).unwrap().is_some());
        thread::sleep(Duration::from_millis(2500));
        assert!(
            !sentinel.exists(),
            "a descendant escaped process containment"
        );
    }

    #[test]
    fn parent_death_cascades_through_supervisor_and_worker() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let sentinel = directory.path().join("escaped");
        let mut command = fixture_command("cascade", &ready);
        command.env(SENTINEL_ENV, &sentinel);
        let mut child = spawn_contained(&mut command, true).unwrap();
        wait_for_path(&ready);

        child.disconnect_parent_for_test();
        assert!(!wait_for_exit(&mut child).success());
        thread::sleep(Duration::from_millis(2500));
        assert!(!sentinel.exists(), "parent death did not cascade to worker");
    }

    fn fixture_command(mode: &str, ready: &std::path::Path) -> ContainedCommand {
        let mut command = ContainedCommand::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "process_control::tests::contained_child_fixture",
                "--nocapture",
            ])
            .env(FIXTURE_ENV, mode)
            .env(READY_ENV, ready)
            .stdout(OutputMode::Null)
            .stderr(OutputMode::Null);
        command
    }

    fn wait_for_path(path: &std::path::Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(Instant::now() < deadline, "fixture did not become ready");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_exit(child: &mut ContainedChild) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "fixture did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
