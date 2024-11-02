use forensic_rs::prelude::{ForensicResult, RegistryReader, RegHiveKey};
use windows::Win32::Storage::FileSystem::GetLogicalDriveStringsW;

fn system_root_from_registry(registry : &mut Box<dyn RegistryReader>) -> ForensicResult<String> {
    let current_version = registry.open_key(RegHiveKey::HkeyLocalMachine, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")?;
    let value: String  = registry.read_value(current_version, "SystemRoot")?.try_into()?;
    Ok(value)
}

fn system_drive_from_registry(registry : &mut Box<dyn RegistryReader>) -> ForensicResult<String> {
    let current_version = registry.open_key(RegHiveKey::HkeyLocalMachine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Setup")?;
    let value: String  = registry.read_value(current_version, "BootDir")?.try_into()?;
    Ok(value)
}

fn program_data_from_registry(registry : &mut Box<dyn RegistryReader>) -> ForensicResult<String> {
    let current_version = registry.open_key(RegHiveKey::HkeyLocalMachine, r"Software\Microsoft\Windows NT\CurrentVersion\ProfileList")?;
    let value: String  = registry.read_value(current_version, "ProgramData")?.try_into()?;
    Ok(value)
}

pub fn system_drive(registry : &mut Box<dyn RegistryReader>) -> String {
    match system_drive_from_registry(registry) {
        Ok(v) => v.to_uppercase(),
        Err(_) => {
            println!(r"Error getting the current SystemDrive from HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\BootDir, returning default C:\");
            format!(r"C:\")
        }
    }
}

pub fn system_root(registry : &mut Box<dyn RegistryReader>) -> String {
    match system_root_from_registry(registry) {
        Ok(v) => v,
        Err(_) => {
            println!(r"Error getting the current SystemRoot from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot, returning default C:\Windows");
            format!(r"C:\")
        }
    }
}

pub fn program_data(registry : &mut Box<dyn RegistryReader>) -> String {
    match program_data_from_registry(registry) {
        Ok(v) => v,
        Err(_) => {
            println!(r"Error getting the current SystemRoot from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList, returning default C:\ProgramData");
            format!(r"C:\ProgramData")
        }
    }
}

pub fn list_users_homes_from_reg(registry : &mut Box<dyn RegistryReader>) -> ForensicResult<Vec<String>> {
    let mut returned = Vec::with_capacity(32);
    let profile_list_key = registry.open_key(RegHiveKey::HkeyLocalMachine, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")?;
    let profile_list = registry.enumerate_keys(profile_list_key)?;
    for profile in &profile_list {
        let profile_key = registry.open_key(profile_list_key, profile)?;
        let profile_image_path : String = registry.read_value(profile_key, "ProfileImagePath")?.try_into()?;
        returned.push(profile_image_path);
    } 
    Ok(returned)
}

pub fn list_users_homes(registry : &mut Box<dyn RegistryReader>) -> Vec<String> {
    match list_users_homes_from_reg(registry) {
        Ok(v) => v,
        Err(_) => {
            println!(r"Error getting the current list_users_homes from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList, returning list of folders in C:\Users");
            let sys_dir = system_drive(registry);
            let mut returned = Vec::with_capacity(32);
            let users_path = std::path::Path::new(&sys_dir).join("Users");
            let readdir = match std::fs::read_dir(users_path) {
                Ok(v) => v,
                Err(_) => return returned
            };
            for dir in readdir {
                let dir = match dir {
                    Ok(v)=> v,
                    Err(_) => continue
                };
                let file_type = match dir.file_type() {
                    Ok(v) => v,
                    Err(_) => continue
                };
                if file_type.is_dir() {
                    returned.push(format!("{:?}", dir.file_name()));
                }
            }
            returned
        }
    }
}

/// List of mounted devices: ["A:\\", "B:\\", "C:\\", "D:\\"]
pub fn mounted_devices() -> Vec<String> {
    let mut to_ret = Vec::with_capacity(32);
    let mut buffer = vec![0u16; 10_000];
    unsafe {
        let readed = GetLogicalDriveStringsW(Some(&mut buffer));
        for txt in buffer[0..readed as usize].split(|n| *n == 0) {
            if txt.len() == 0{
                continue;
            }
            to_ret.push(String::from_utf16_lossy(txt));
        }
    }
    
    to_ret
}

#[cfg(test)]
mod tst {
    use forensic_rs::prelude::RegistryReader;
    use frnsc_liveregistry_rs::LiveRegistryReader;

    use super::*;

    #[test]
    fn mnt(){
        println!("{:?}",mounted_devices());
    }


    fn get_registry_reader() -> Box<dyn RegistryReader> {
        let registry = LiveRegistryReader::new();
        let registry : Box<dyn RegistryReader> = Box::new(registry);
        registry
    }
    #[test]
    fn should_return_system_root_c() {
        let mut registry = get_registry_reader();
        let var : String = system_root(&mut registry).to_uppercase();
        assert_eq!(r"C:\WINDOWS", var);
    }
    #[test]
    fn should_return_system_root_c_reg() {
        let mut registry = get_registry_reader();
        let var : String = system_root_from_registry(&mut registry).unwrap().to_uppercase();
        assert_eq!(r"C:\WINDOWS", var);
    }

    #[test]
    fn should_retur_system_drive_c() {
        let mut registry = get_registry_reader();
        let var : String = system_drive(&mut registry);
        assert_eq!(r"C:\", var);
    }
    #[test]
    fn should_retur_system_drive_c_reg() {
        let mut registry = get_registry_reader();
        let var : String = system_drive_from_registry(&mut registry).unwrap();
        assert_eq!(r"C:\", var);
    }

    #[test]
    fn should_return_users_homes() {
        let mut registry = get_registry_reader();
        let var : Vec<String> = list_users_homes(&mut registry);
        println!("{:?}", var);
    }
}