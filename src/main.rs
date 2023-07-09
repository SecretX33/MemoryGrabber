#![allow(unused_imports)]
#![allow(dead_code)]

use anyhow::Result;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::util::windows::process::{find_address_from_offset, find_process_id, open_process, strip_trailing_nulls};

mod util;

fn main() -> Result<()> {
    let notepad_name = "notepad.exe";
    let notepad_process_id = find_process_id(notepad_name)?.expect(&format!("{} is not running", notepad_name));
    println!("Notepad ID is {}", notepad_process_id);

    let process_handle = open_process(notepad_process_id)?;
    let address = find_address_from_offset(notepad_process_id, "textinputframework.dll", 0xE83E4)?.unwrap();
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