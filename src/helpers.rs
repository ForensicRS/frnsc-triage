use forensic_rs::err::{ForensicError, ForensicResult};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, HANDLE},
        Storage::FileSystem::{
            CreateFileW, GetDiskFreeSpaceW, GetFileSize, ReadFile, SetFilePointerEx, FILE_BEGIN, FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING
        }, System::{Ioctl::{FSCTL_GET_RETRIEVAL_POINTERS, STARTING_VCN_INPUT_BUFFER}, IO::DeviceIoControl},
    },
};

pub fn to_pcwstr(txt: &str) -> Vec<u16> {
    let mut val = txt.encode_utf16().collect::<Vec<u16>>();
    val.push(0);
    val
}

pub fn encode_pcwstr(txt: &str, buffer : &mut Vec<u16>) {
    buffer.clear();
    for d in txt.encode_utf16() {
        buffer.push(d);
    }
    buffer.push(0);
}

pub fn replace_envvars(
    txt: &str,
    system_drive: &str,
    system_root: &str,
    prog_data: &str,
) -> String {
    let pos = match txt[..].find(r"%\") {
        Some(pos) => pos,
        None => return txt.to_string(),
    };

    let variable = &txt[1..pos];
    if is_system_drive_env(variable) {
        return if system_drive.ends_with(r"\") {
            format!(r"{}{}", system_drive, &txt[pos + 2..])
        } else {
            format!(r"{}\{}", system_drive, &txt[pos + 2..])
        };
    } else if is_system_root_env(variable) {
        return if system_root.ends_with(r"\") {
            format!(r"{}{}", system_root, &txt[pos + 2..])
        } else {
            format!(r"{}\{}", system_root, &txt[pos + 2..])
        };
    } else if is_program_data_env(variable) {
        return if prog_data.ends_with(r"\") {
            format!(r"{}{}", prog_data, &txt[pos + 2..])
        } else {
            format!(r"{}\{}", prog_data, &txt[pos + 2..])
        };
    }
    txt.to_string()
}

pub fn replace_home_vars(txt: &str, homes: &Vec<String>) -> Vec<String> {
    let pos = match txt[..].find(r"%\") {
        Some(pos) => pos,
        None => return vec![],
    };
    let mut to_ret = Vec::with_capacity(32);
    for home in homes {
        if home.ends_with(r"\") {
            to_ret.push(format!(r"{}{}", home, &txt[pos + 2..]));
        } else {
            to_ret.push(format!(r"{}\{}", home, &txt[pos + 2..]));
        }
    }
    to_ret
}

pub fn contains_env_var(txt: &str) -> bool {
    txt.starts_with("%")
}

pub fn is_system_drive_env(txt: &str) -> bool {
    if txt.len() != "systemdrive".len() {
        return false;
    }
    txt.to_uppercase() == "SYSTEMDRIVE"
}
pub fn is_system_root_env(txt: &str) -> bool {
    if txt.len() != "systemroot".len() {
        return false;
    }
    txt.to_uppercase() == "SYSTEMROOT"
}
pub fn is_program_data_env(txt: &str) -> bool {
    if txt.len() != "programdata".len() {
        return false;
    }
    txt.to_uppercase() == "PROGRAMDATA"
}

pub fn is_user_home_env(txt: &str) -> bool {
    txt.starts_with("%USERHOME%")
}

/// Obtains the Drive path and Disk base path
pub fn get_drive_and_disk(pth: &str) -> ForensicResult<(String, String)> {
    let position = match pth.find(":") {
        Some(v) => v,
        None => {
            return Err(ForensicError::bad_format_str(
                "Cannot find disk letter in path",
            ))
        }
    };
    if position != 1 {
        return Err(ForensicError::bad_format_str(
            "Cannot find disk letter in path",
        ));
    }
    Ok((
        format!("\\\\.\\{}:", &pth[0..position]),
        format!("{}:\\", &pth[0..position]),
    ))
}

pub fn get_drive_metadata(pth: &str, buffer : &mut Buffer) -> ForensicResult<(HANDLE, u32, u32)> {
    let (drive_path, disk_letter) = get_drive_and_disk(pth)?;
    let mut disk_name = buffer.u16_vec();
    encode_pcwstr(&drive_path, &mut disk_name);
    let disk_pointer = match unsafe {
        CreateFileW(
            PCWSTR::from_raw(disk_name.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    } {
        Ok(v) => v,
        Err(e) => return Err(ForensicError::Other(format!("{}", e))),
    };
    let mut sectors_in_cluster = 0;
    let mut bytes_per_sector = 0;
    let mut free_clusters = 0;
    let mut total_clusters = 0;
    encode_pcwstr(&disk_letter, &mut disk_name);
    if let Err(e) = unsafe {
        GetDiskFreeSpaceW(
            PCWSTR::from_raw(disk_name.as_ptr()),
            Some(&mut sectors_in_cluster),
            Some(&mut bytes_per_sector),
            Some(&mut free_clusters),
            Some(&mut total_clusters),
        )
    } {
        let _ = unsafe { CloseHandle(disk_pointer) };
        return Err(ForensicError::Other(format!(
            "Cannot retrieve Disk Info: {}",
            e
        )));
    }
    Ok((disk_pointer, sectors_in_cluster, bytes_per_sector))
}

pub fn get_file_pointer_and_size(pth: &str, buffer : &mut Buffer) -> ForensicResult<(HANDLE, u64)>{
    let filename = format!("\\\\.\\{}\0", pth);
    let mut buff = buffer.u16_vec();
    encode_pcwstr(&filename, &mut buff);
    let file_pointer = match unsafe {
        CreateFileW(
            PCWSTR::from_raw(buff.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    } {
        Ok(v) => v,
        Err(e) => return Err(ForensicError::Other(format!("{}", e.message()))),
    };
    let mut file_size_high = 0;
    let file_size_low = unsafe {GetFileSize(file_pointer, Some(&mut file_size_high))};
    let file_size = ((file_size_high as u64) << 32) | (file_size_low as u64);

    Ok((file_pointer, file_size))
}

pub fn get_retrieval_pointers(file_pointer : HANDLE, buffer : &mut Buffer) -> ForensicResult<RetrievalPointersBuffer> {
    let mut in_buffer = STARTING_VCN_INPUT_BUFFER::default();
    let mut bytes_returned = 0;
    let buff = buffer.u8();
    let buffer_size: u32 = buff.len() as u32;
    if let Err(e) = unsafe {DeviceIoControl(
        file_pointer,
        FSCTL_GET_RETRIEVAL_POINTERS,
        Some(std::ptr::addr_of_mut!(in_buffer) as _),
        std::mem::size_of::<STARTING_VCN_INPUT_BUFFER>() as u32,
        Some(buff.as_mut_ptr() as _),
        buffer_size,
        Some(&mut bytes_returned),
        None,
    )} {
        return Err(ForensicError::Other(format!("Cannot retrive FSCTL pointers: {}", e)))
    }
    let retrieval_pinters = buffer_to_retrieval_pointers(&buff);
    Ok(retrieval_pinters)
}

pub fn move_disk_position(disk_pointer : HANDLE, offset : i64) -> Result<(), std::io::Error> {
    if let Err(e) = unsafe{ SetFilePointerEx(disk_pointer, offset, None, FILE_BEGIN) } {
        let res : i32 = e.code().0;
        let e = std::io::Error::from_raw_os_error(res);
        return Err(e);
    }
    Ok(())
}

pub fn read_file_from_disk_pointer_buffered(disk_pointer : HANDLE, buffer : &mut Buffer, to_be_readed : u32) -> Result<u32, std::io::Error> {
    let buf = buffer.u8();
    let buf = &mut buf[0..to_be_readed as usize];
    let mut readed_bytes = 0;
    if let Err(e) = unsafe {ReadFile(
        disk_pointer,
        Some(buf),
        Some(&mut readed_bytes),
        None,
    ) } {
        let res : i32 = e.code().0;
        let e = std::io::Error::from_raw_os_error(res);
        return Err(e);
    }
    Ok(readed_bytes)
}

pub fn read_file_from_disk_pointer(disk_pointer : HANDLE, buf : &mut [u8], to_be_readed : u32) -> Result<u32, std::io::Error> {
    if buf.len() < to_be_readed as usize {
        return Err(std::io::Error::from_raw_os_error(ERROR_INSUFFICIENT_BUFFER.0 as _))
    }
    let buf = &mut buf[0..to_be_readed as usize];
    let mut readed_bytes = 0;
    if let Err(e) = unsafe {ReadFile(
        disk_pointer,
        Some(buf),
        Some(&mut readed_bytes),
        None,
    ) } {
        let res : i32 = e.code().0;
        let e = std::io::Error::from_raw_os_error(res);
        return Err(e);
    }
    Ok(readed_bytes)
}

pub fn buffer_to_retrieval_pointers(vc: &[u8]) -> RetrievalPointersBuffer {
    let extent_count = u32::from_le_bytes([vc[0], vc[1], vc[2], vc[3]]);
    let starting_vcn = i64::from_le_bytes(vc[8..16].try_into().unwrap());
    let mut extents = Vec::with_capacity(extent_count as usize);
    let mut offset = 16;
    for _ in 0..extent_count {
        let next_vcn = i64::from_le_bytes(vc[offset..offset + 8].try_into().unwrap());
        let lcn = i64::from_le_bytes(vc[offset + 8..offset + 16].try_into().unwrap());
        offset += 16;
        extents.push(PointerExtent { next_vcn, lcn });
    }
    RetrievalPointersBuffer {
        extent_count,
        starting_vcn,
        extents,
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct RetrievalPointersBuffer {
    pub extent_count: u32,
    pub starting_vcn: i64,
    pub extents: Vec<PointerExtent>,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct PointerExtent {
    pub next_vcn: i64,
    pub lcn: i64,
}

/// Buffer that simplifies working with u8 and u16. Its too complex to transmute a single u8 vector into a u16 vector. So its better to initialize two
pub struct Buffer {
    u8 : Vec<u8>,
    u16 : Vec<u16>
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            u8 : vec![0u8; 1024],
            u16 : vec![0u16; 1024]
        }
    }
    pub fn with_capacity(size : usize) -> Self {
        Self {
            u8 : vec![0u8; size],
            u16 :vec![0u16; size]
        }
    }

    pub fn push(&mut self, v : u8) {
        self.u8.push(v);
    }

    pub fn u8(&mut self) -> &mut [u8] {
        &mut self.u8
    }

    pub fn u16(&mut self) -> &mut [u16] {
        &mut self.u16
    }
    pub fn u16_vec(&mut self) -> &mut Vec<u16> {
        &mut self.u16
    }
    pub fn u8_vec(&mut self) -> &mut Vec<u8> {
        &mut self.u8
    }
    pub fn reset(&mut self) {
        unsafe {
            self.u8.set_len(self.u8.capacity());
            self.u16.set_len(self.u16.capacity());
        }
    }
    pub fn set_len(&mut self, length : usize) {
        unsafe {
            let u8l = self.u8.capacity().min(length);
            self.u8.set_len(u8l);
            let u16l = self.u16.capacity().min(length);
            self.u16.set_len(u16l);
        }
    }
}