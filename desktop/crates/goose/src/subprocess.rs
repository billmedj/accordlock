use tokio::process::Command;

#[cfg(windows)]
const CREATE_NO_WINDOW_FLAG: u32 = 0x08000000;

/// Authority used by Goose to talk to the trusted AccordLock runtime must
/// never be inherited by a provider, hook, extension, or model-launched shell.
/// The parent process may hold these values; every child process gets an
/// explicit tombstone for every authority-bearing variable.
const ACCORDLOCK_RUNTIME_ENV: [&str; 3] = [
    "ACCORDLOCK_RUNTIME_URL",
    "ACCORDLOCK_RUNTIME_TOKEN",
    "ACCORDLOCK_BACKEND_BINDING_SECRET",
];

pub(crate) fn scrub_accordlock_authority(command: &mut Command) {
    for key in ACCORDLOCK_RUNTIME_ENV {
        command.env_remove(key);
    }
}

pub(crate) fn scrub_accordlock_authority_std(command: &mut std::process::Command) {
    for key in ACCORDLOCK_RUNTIME_ENV {
        command.env_remove(key);
    }
}

#[cfg(target_os = "linux")]
fn configure_parent_death_signal(command: &mut Command) {
    let parent_pid = unsafe { libc::getpid() };

    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            if libc::getppid() != parent_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }

            Ok(())
        });
    }
}

pub trait SubprocessExt {
    fn set_no_window(&mut self) -> &mut Self;
}

/// Creates a Git command that rejects implicit bare repositories and cannot run a
/// repository-configured fsmonitor hook.
pub fn git_command() -> std::process::Command {
    let mut command = std::process::Command::new("git");
    scrub_accordlock_authority_std(&mut command);
    command.args([
        "-c",
        "safe.bareRepository=explicit",
        "-c",
        "core.fsmonitor=false",
    ]);
    command
}

impl SubprocessExt for Command {
    fn set_no_window(&mut self) -> &mut Self {
        scrub_accordlock_authority(self);
        #[cfg(windows)]
        {
            self.creation_flags(CREATE_NO_WINDOW_FLAG);
        }
        self
    }
}

impl SubprocessExt for std::process::Command {
    fn set_no_window(&mut self) -> &mut Self {
        scrub_accordlock_authority_std(self);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            self.creation_flags(CREATE_NO_WINDOW_FLAG);
        }
        self
    }
}

#[allow(unused_variables)]
pub fn configure_subprocess(command: &mut Command) {
    // Isolate subprocess into its own process group so it does not receive
    // SIGINT when the user presses Ctrl+C in the terminal.
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(target_os = "linux")]
    configure_parent_death_signal(command);
    command.set_no_window();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_explicit_removal<'a>(
        envs: &[(&'a std::ffi::OsStr, Option<&'a std::ffi::OsStr>)],
        expected: &str,
    ) -> bool {
        envs.iter()
            .any(|(key, value)| *key == std::ffi::OsStr::new(expected) && value.is_none())
    }

    #[test]
    fn tokio_children_cannot_inherit_runtime_authority() {
        let mut command = Command::new("ignored");
        command
            .env("ACCORDLOCK_RUNTIME_URL", "http://127.0.0.1:43127")
            .env("ACCORDLOCK_RUNTIME_TOKEN", "secret")
            .env("ACCORDLOCK_BACKEND_BINDING_SECRET", "binding-secret")
            .set_no_window();

        let envs: Vec<_> = command.as_std().get_envs().collect();
        assert!(has_explicit_removal(&envs, "ACCORDLOCK_RUNTIME_URL"));
        assert!(has_explicit_removal(&envs, "ACCORDLOCK_RUNTIME_TOKEN"));
        assert!(has_explicit_removal(
            &envs,
            "ACCORDLOCK_BACKEND_BINDING_SECRET"
        ));
    }

    #[test]
    fn std_children_cannot_inherit_runtime_authority() {
        let mut command = std::process::Command::new("ignored");
        command
            .env("ACCORDLOCK_RUNTIME_URL", "http://127.0.0.1:43127")
            .env("ACCORDLOCK_RUNTIME_TOKEN", "secret")
            .env("ACCORDLOCK_BACKEND_BINDING_SECRET", "binding-secret")
            .set_no_window();

        let envs: Vec<_> = command.get_envs().collect();
        assert!(has_explicit_removal(&envs, "ACCORDLOCK_RUNTIME_URL"));
        assert!(has_explicit_removal(&envs, "ACCORDLOCK_RUNTIME_TOKEN"));
        assert!(has_explicit_removal(
            &envs,
            "ACCORDLOCK_BACKEND_BINDING_SECRET"
        ));
    }
}
