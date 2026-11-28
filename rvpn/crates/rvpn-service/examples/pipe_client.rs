//! Dev client for `\\.\pipe\rvpn-service`: sends Ping, Status and Connect
//! and prints each reply. Run against `rvpn-service.exe --console`.

use std::fs::OpenOptions;
use std::io::{Read, Write};

fn exchange(pipe: &mut std::fs::File, request_json: &str) -> std::io::Result<String> {
    let payload = request_json.as_bytes();
    let len = (payload.len() as u32).to_le_bytes();
    pipe.write_all(&len)?;
    pipe.write_all(payload)?;
    pipe.flush()?;

    let mut len_buf = [0u8; 4];
    pipe.read_exact(&mut len_buf)?;
    let reply_len = u32::from_le_bytes(len_buf) as usize;
    let mut reply = vec![0u8; reply_len];
    pipe.read_exact(&mut reply)?;
    Ok(String::from_utf8_lossy(&reply).into_owned())
}

fn main() -> std::io::Result<()> {
    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(r"\\.\pipe\rvpn-service")?;
    for req in ["\"Ping\"", "\"Status\"", "\"Connect\""] {
        let reply = exchange(&mut pipe, req)?;
        println!("{req} -> {reply}");
    }
    Ok(())
}
