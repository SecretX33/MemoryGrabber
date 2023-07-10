#![allow(unused_imports)]
#![allow(dead_code)]

use anyhow::Result;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::util::windows::process::{find_multilevel_pointer_from_offsets, find_process_id, open_process, strip_trailing_nulls};

mod util;

fn main() -> Result<()> {
    let mpc_name = "mpc-hc64.exe";
    let process_id = find_process_id(mpc_name)?.expect(&format!("{} is not running", mpc_name));
    println!("Notepad ID is {}", process_id);

    let process_handle = open_process(process_id)?;
    let address = find_multilevel_pointer_from_offsets(process_id, &process_handle, "mpc-hc64.exe", &vec![0x0079A8E0, 0x1F0, 0x2C8, 0x20, 0x38])?.unwrap();
    println!("Address: {:?}", address);

    // Read the memory of the notepad process
    let mut buffer = [0u16; 1024];
    let mut bytes_read = 0;

    let read_memory_successfully = unsafe {
        ReadProcessMemory(
            *process_handle,
            address,
            buffer.as_mut_ptr() as _,
            buffer.len(),
            Some(&mut bytes_read),
        ).as_bool()
    };

    if read_memory_successfully {
        let text = String::from_utf16_lossy(strip_trailing_nulls(&buffer[..bytes_read]));
        println!("Memory content: {}", text);
    } else {
        println!("Failed to read process memory. Error: {:?}", unsafe { GetLastError() });
    }

    Ok(())
}