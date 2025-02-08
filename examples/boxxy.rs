use acme_redirect::args::DaemonArgs;
use boxxy::shprintln;

fn stage1(sh: &mut boxxy::Shell, _args: Vec<String>) -> Result<(), boxxy::Error> {
    shprintln!(sh, "[*] starting stage1");
    acme_redirect::sandbox::init(&DaemonArgs {
        bind_addr: Some("[::]:80".to_string()),
        chroot: true,
        user: Some("nobody".to_string()),
    })
    .unwrap();
    shprintln!(sh, "[+] activated!");
    Ok(())
}

fn main() {
    env_logger::init();

    println!("stage1        activate sandbox");

    let toolbox = boxxy::Toolbox::new().with(vec![("stage1", stage1)]);
    boxxy::Shell::new(toolbox).run()
}
