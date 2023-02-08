use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("aya-tracepoint-ebpf/src");
    let names: Vec<&str> = vec!["ethhdr", "iphdr", "udphdr", "sock", "sock_common"];
    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;
    let mut out = File::create(dir.join("binding.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}
