use crate::errors::*;
use nix::unistd::{Gid, Uid};
use std::fs;
use std::fs::{Metadata, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use users::{Group, User};

pub fn ensure_chmod(path: &Path, md: &Metadata, mode: u32) -> Result<()> {
    if md.mode() != mode {
        debug!("Setting mode of {:?} to {:#o}", path, mode);
        fs::set_permissions(path, Permissions::from_mode(mode))
            .context("Failed to set permissions of data directory")?;
    } else {
        debug!(
            "Mode of {:?} is already set correctly, not changing it",
            path
        );
    }
    Ok(())
}

pub fn ensure_chown(path: &Path, md: &Metadata, owner: &User) -> Result<()> {
    if owner.uid() != md.uid() {
        let uid = Uid::from_raw(owner.uid());
        debug!("Setting owner of {:?} to {:?}", path, owner.name());
        nix::unistd::chown(path, Some(uid), None).with_context(|| {
            anyhow!("Failed to change owner of {:?} to {:?}", path, owner.name())
        })?;
    } else {
        debug!("Owner of data directory is already set correctly, not changing it");
    }
    Ok(())
}

pub fn ensure_chgrp(path: &Path, md: &Metadata, group: &Group) -> Result<()> {
    if group.gid() != md.gid() {
        let gid = Gid::from_raw(group.gid());
        debug!("Setting group of {:?} to {:?}", path, group.name());
        nix::unistd::chown(path, None, Some(gid)).with_context(|| {
            anyhow!("Failed to change group of {:?} to {:?}", path, group.name())
        })?;
    } else {
        debug!("Group of data directory is already set correctly, not changing it");
    }
    Ok(())
}
