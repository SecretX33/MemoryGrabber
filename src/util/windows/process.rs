use std::ffi::c_void;
use anyhow::{bail, Result};
use scopeguard::{guard, ScopeGuard};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use crate::util::windows::string::ToPCWSTRWrapper;

pub fn open_process(process_id: u32) -> Result<ManagedHandle> {
    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_id) }
        ?.require_valid(&format!("Failed to open process {}. Error: {:?}", process_id, unsafe { GetLastError() }))
        ?.to_managed();
    Ok(process_handle)
}

pub fn find_process_id(process_name: &str) -> Result<Option<u32>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        ?.require_valid(&format!("Failed to create process list snapshot. Error: {:?}", unsafe { GetLastError() }))
        ?.to_managed();

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

pub fn get_process_name(process_entry: &PROCESSENTRY32W) -> String {
    String::from_utf16_lossy(strip_trailing_nulls(&process_entry.szExeFile))
}

pub fn find_address_from_offset(process_id: u32, module_name: &str, offset: isize) -> Result<Option<*const c_void>> {
    let base_address = find_module_base_address(process_id, module_name)?;
    Ok(base_address.map(|p| p.wrapping_offset(offset)))
}

pub fn find_module_base_address(process_id: u32, module_name: &str) -> Result<Option<*const c_void>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id) }
        ?.require_valid(&format!("Failed to create module list snapshot for process {}. Error: {:?}", process_id, unsafe { GetLastError() }))
        ?.to_managed();

    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let entry_ptr = &mut module_entry as *mut MODULEENTRY32W;

    if unsafe { Module32FirstW(*snapshot, entry_ptr).as_bool() } {
        println!("Scanning module snapshot to find process ID of {}", module_name);
        loop {
            let name = get_module_name(&module_entry);
            if name == module_name {
                let base_address = module_entry.modBaseAddr as *const c_void;
                println!("Module found: {} (base address: {:?})", name, base_address);

                return Ok(match base_address.is_null() {
                    true => None,
                    false => Some(base_address),
                });
            }
            if unsafe { !Module32NextW(*snapshot, entry_ptr).as_bool() } {
                break;
            }
        }
    }

    return Ok(None);
}

pub fn get_module_name(module_entry: &MODULEENTRY32W) -> String {
    String::from_utf16_lossy(strip_trailing_nulls(&module_entry.szModule))
}

pub fn strip_trailing_nulls(slice: &[u16]) -> &[u16] {
    let stripped_len = slice.iter().position(|&e| e == 0).unwrap_or(slice.len());
    &slice[..stripped_len]
}

/// A HANDLE that automatically closes itself when dropped.
pub type ManagedHandle = ScopeGuard<HANDLE, fn(HANDLE)>;

pub trait HandleExt {
    fn to_managed(&self) -> ManagedHandle;
    fn require_valid(&self, message: &str) -> Result<&Self>;
}

impl HandleExt for HANDLE {
    fn to_managed(&self) -> ManagedHandle {
        guard(
            *self,
            |h| if !h.is_invalid() {
                unsafe { CloseHandle(h); }
            },
        )
    }

    fn require_valid(&self, error_message: &str) -> Result<&Self> {
        if self.is_invalid() {
            bail!(error_message.to_owned());
        }
        return Ok(&self)
    }
}
