use crate::chall::Challenge;
use crate::errors::*;
use crate::persist::FilePersist;
use acme_lib::create_p384_key;
use acme_lib::{Directory, DirectoryUrl};
use acme_lib::persist::{Persist, PersistKey, PersistKind, MemoryPersist};

const REALM: &str = ""; // dummy

#[derive(Debug)]
pub struct Request<'a> {
    pub acme_url: &'a str,
    pub account_email: Option<&'a str>,
    pub primary_name: &'a str,
    pub alt_names: &'a [String],
}

fn try_load_acc(persist: &FilePersist, mem: &MemoryPersist) -> Result<bool> {
    if let Some(acc) = persist.load_acc_privkey()? {
        let p = PersistKey::new(REALM, PersistKind::AccountPrivateKey , REALM);
        mem.put(&p, acc.as_bytes()).unwrap();
        Ok(true)
    } else {
        Ok(false)
    }
}

fn get_acc_key(mem: &MemoryPersist) -> String {
    let p = PersistKey::new(REALM, PersistKind::AccountPrivateKey , REALM);
    let privkey = mem.get(&p).unwrap().unwrap();
    String::from_utf8(privkey).unwrap()
}

pub fn request(persist: FilePersist, challenge: &mut Challenge, req: &Request) -> Result<()> {
    let url = DirectoryUrl::Other(&req.acme_url);

    // Create a directory entrypoint.
    let mem = MemoryPersist::new();

    let already_existed = try_load_acc(&persist, &mem)?;
    let dir = Directory::from_url(mem.clone(), url)?;

    info!("authenticating with account");
    let acc = dir.account_with_realm(REALM, vec![])?;
    if !already_existed {
        info!("saving private key for newly registered account");
        let privkey = get_acc_key(&mem);
        persist.store_acc_privkey(&privkey)?;
    }

    // Order a new TLS certificate for a domain.
    let alt_names = req.alt_names.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    info!("sending certificate order");
    let mut ord_new = acc.new_order(&req.primary_name, &alt_names)?;

    // If the ownership of the domain(s) have already been
    // authorized in a previous order, you might be able to
    // skip validation. The ACME API provider decides.
    let ord_csr = loop {
        // are we done?
        if let Some(ord_csr) = ord_new.confirm_validations() {
            info!("order has been confirmed");
            break ord_csr;
        }

        // Get the possible authorizations (for a single domain
        // this will only be one element).
        info!("fetch necessary authentications");
        let auths = ord_new.authorizations()?;

        // For HTTP, the challenge is a text file that needs to
        // be placed in your web server's root:
        //
        // /var/www/.well-known/acme-challenge/<token>
        //
        // The important thing is that it's accessible over the
        // web for the domain(s) you are trying to get a
        // certificate for:
        //
        // http://mydomain.io/.well-known/acme-challenge/<token>
        for auth in &auths {
            let chall = auth.http_challenge();

            // The token is the filename.
            let token = chall.http_token();

            // The proof is the contents of the file
            let proof = chall.http_proof();

            // Place the proof
            challenge.write(token, &proof)?;

            // After the file is accessible from the web, the calls
            // this to tell the ACME API to start checking the
            // existence of the proof.
            //
            // The order at ACME will change status to either
            // confirm ownership of the domain, or fail due to the
            // not finding the proof. To see the change, we poll
            // the API with 5000 milliseconds wait between.
            chall.validate(5000)?;
        }

        // Update the state against the ACME API.
        ord_new.refresh()?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience, you
    // can provide your own keypair instead if you want.
    let pkey_pri = create_p384_key();

    // Submit the CSR. This causes the ACME provider to enter a
    // state of "processing" that must be polled until the
    // certificate is either issued or rejected. Again we poll
    // for the status change.
    let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000)?;

    // Now download the certificate. Also stores the cert in
    // the persistence.
    info!("downloading certificate");
    let cert = ord_cert.download_and_save_cert()?;

    info!("storing certificate");
    persist
        .store_cert(&req.primary_name, &cert)
        .context("Failed to store certificate")?;

    Ok(())
}
