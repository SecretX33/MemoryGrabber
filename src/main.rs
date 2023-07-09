#![allow(unused_imports)]
#![allow(dead_code)]

use std::os::raw::c_void;
use std::ptr;
use std::rc::Rc;
use std::slice::Iter;
use anyhow::{bail, Result};
use scopeguard::{defer, guard, ScopeGuard};
use System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::*;
use windows::Win32::System::Diagnostics::ToolHelp::{Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

fn main() -> Result<()> {
    let notepad_name = "notepad.exe";
    let notepad_process_id = find_process_id(notepad_name)?.expect(&format!("{} is not running", notepad_name));
    println!("Notepad ID is {}", notepad_process_id);

    let process_handle = open_process(notepad_process_id)?;

    // Read the memory of the notepad process
    let mut buffer = [0u16; 1024];
    let mut bytes_read = 0;
    let address = 0x27CE0AE02A0 as *const c_void;

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
        let valid_buffer_contents = strip_trailing_nulls(buffer[..bytes_read].iter());
        let text = String::from_utf16_lossy(&valid_buffer_contents);
        println!("Memory content: {}", text);
    } else {
        println!("Failed to read process memory. Error: {:?}", unsafe { GetLastError() });
    }

    Ok(())
}

fn open_process(process_id: u32) -> Result<RcHandle> {
    let process_handle = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, process_id)?
    };
    if process_handle.is_invalid() {
        bail!("Failed to open process {}. Error: {:?}", process_id, unsafe { GetLastError() });
    }
    Ok(close_when_dropped(process_handle))
}

fn close_when_dropped(handle: HANDLE) -> RcHandle {
    guard(
        handle,
        |h| if !h.is_invalid() {
            unsafe { CloseHandle(h); }
        },
    )
}

fn find_process_id(process_name: &str) -> Result<Option<u32>> {
    let snapshot = close_when_dropped(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? });
    if snapshot.is_invalid() {
        bail!("Failed to create process list snapshot. Error: {:?}", unsafe { GetLastError() });
    }

    let mut process_entry = PROCESSENTRY32W::default();
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let entry_ptr = &mut process_entry as *mut PROCESSENTRY32W;

    if unsafe { Process32FirstW(*snapshot, entry_ptr).as_bool() } {
        println!("Scanning process snapshot to find process ID of {}", process_name);
        loop {
            let name = get_process_name(&process_entry);
            if name == process_name {
                println!("Process found: {} (id: {})", name, process_entry.th32ProcessID);
                return Ok(Some(process_entry.th32ProcessID));
            }
            if unsafe { !Process32NextW(*snapshot, entry_ptr).as_bool() } {
                break;
            }
        }
    }

    return Ok(None);
}

fn get_process_name(process_entry: &PROCESSENTRY32W) -> String {
    String::from_utf16_lossy(&strip_trailing_nulls(process_entry.szExeFile.iter()))
}

fn strip_trailing_nulls(iter: Iter<u16>) -> Vec<u16> {
    iter.take_while(|&&e| e != 0)
        .map(|a| a.clone())
        .collect::<Vec<_>>()
} 

type RcHandle = ScopeGuard<HANDLE, fn(HANDLE)>;