use crate::args::DaemonArgs;
use crate::errors::*;
use caps::CapSet;
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
    debug!("Permanently clearing capability sets");
    caps::clear(None, CapSet::Effective)
        .map_err(|err| anyhow!("Failed to clear effective capability set: {}", err))?;
    caps::clear(None, CapSet::Permitted)
        .map_err(|err| anyhow!("Failed to clear permitted capability set: {}", err))?;
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
        nix::unistd::setgroups(&[]).context("Failed to clear supplementary groups")?;
        nix::unistd::setgid(gid).context("Failed to drop gid")?;
        nix::unistd::setuid(uid).context("Failed to drop uid")?;
    }

    drop_caps()?;

    Ok(())
}
