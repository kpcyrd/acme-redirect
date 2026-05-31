use crate::args::DaemonArgs;
use crate::errors::*;
use nix::unistd::{Gid, Uid};
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

fn chroot(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;

    if !metadata.is_dir() {
        bail!("chroot target is no directory");
    }

    if metadata.uid() != 0 {
        bail!("chroot target isn't owned by root");
    }

    if metadata.mode() & 0o22 != 0 {
        bail!("chroot is writable by group or world");
    }

    nix::unistd::chroot(path)?;
    env::set_current_dir("/")?;
    Ok(())
}

fn drop_caps() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use caps::CapSet;
        debug!("Permanently clearing capability sets");
        caps::clear(None, CapSet::Effective)
            .map_err(|err| anyhow!("Failed to clear effective capability set: {}", err))?;
        caps::clear(None, CapSet::Permitted)
            .map_err(|err| anyhow!("Failed to clear permitted capability set: {}", err))?;
    }
    Ok(())
}

fn landlock() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
            path_beneath_rules,
        };

        let path = env::current_dir().context("Failed to determine current directory")?;

        let abi = landlock::ABI::V1;
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))?
            .create()?
            .add_rules(path_beneath_rules(&[path], AccessFs::from_read(abi)))?
            .restrict_self()?;

        match status.ruleset {
            RulesetStatus::FullyEnforced => info!("Successfully enabled landlock rules"),
            RulesetStatus::PartiallyEnforced => {
                warn!("Partially enabled landlock rules, please update your kernel")
            }
            RulesetStatus::NotEnforced => bail!("Could not enforce, please update your kernel"),
        }
    }

    Ok(())
}

pub fn init(args: &DaemonArgs) -> Result<()> {
    let user = if let Some(name) = &args.user {
        debug!("Resolving uid for {:?}", name);
        let user = uzers::get_user_by_name(&name)
            .ok_or_else(|| anyhow!("Failed to look up user: {:?}", name))?;
        let uid = Uid::from_raw(user.uid());
        let gid = Gid::from_raw(user.primary_group_id());
        debug!("Resolved {:?} => {}:{}", name, uid, gid);
        Some((uid, gid))
    } else {
        None
    };

    if args.chroot {
        let path = env::current_dir().context("Failed to determine current directory")?;
        debug!("Chrooting into {:?}", path);
        chroot(&path).context("Failed to chroot")?;
    }

    if let Some((uid, gid)) = user {
        debug!("Dropping uid:gid to {}:{}", uid, gid);
        // Remove the `cfg(...)` after this lands: https://github.com/nix-rust/nix/pull/2793
        #[cfg(not(target_os = "macos"))]
        nix::unistd::setgroups(&[]).context("Failed to clear supplementary groups")?;
        nix::unistd::setgid(gid).context("Failed to drop gid")?;
        nix::unistd::setuid(uid).context("Failed to drop uid")?;
    }

    drop_caps()?;

    if let Err(err) = landlock() {
        // This is intentionally not a fatal error, so you can run acme-redirect on kernels
        // without landlock support.
        // On most deployments, the same effect of having filesystem access restricted to a
        // ready-only webroot (and nothing else) is already enforced through chroot and
        // filesystem permissions.
        warn!("Failed to set up landlock: {err:#}");
    }

    Ok(())
}
