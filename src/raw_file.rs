use forensic_rs::prelude::{ForensicError, ForensicResult};
use std::io::{Read, Write};
use std::path::Path;
use windows::core::PCWSTR;
use windows::imp::GetLastError;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetDiskFreeSpaceW, GetFileSize, ReadFile, SetFilePointerEx, FILE_BEGIN,
    FILE_READ_ATTRIBUTES,
};
use windows::Win32::System::Ioctl::{FSCTL_GET_RETRIEVAL_POINTERS, STARTING_VCN_INPUT_BUFFER};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::{
    Foundation::GENERIC_READ,
    Storage::FileSystem::{
        FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    },
};

pub fn to_pcwstr(txt: &str) -> Vec<u16> {
    let mut val = txt.encode_utf16().collect::<Vec<u16>>();
    val.push(0);
    val
}

pub struct RawFile {
    pub disk_pointer: HANDLE,
    pub file_size: u64,
    pub ret_pointers: RetrievalPointersBuffer,
    pub buffer_for_cluster: usize,
    pub extent_i: usize,
    pub readed_bytes: usize,
    pub cluster_i: usize,
}

impl RawFile {
    pub fn open<P: AsRef<Path>>(path: P) -> ForensicResult<Self> {
        let path = path.as_ref();
        let pth = match path.to_str() {
            Some(v) => v,
            None => return Err(ForensicError::Missing),
        };
        let (disk_path, disk_letter) = match pth.find(":") {
            Some(v) => {
                if v != 1 {
                    return Err(ForensicError::BadFormat);
                }
                (
                    format!("\\\\.\\{}:", &pth[0..v]),
                    format!("{}:\\", &pth[0..v]),
                )
            }
            None => return Err(ForensicError::BadFormat),
        };
        let (disk_pointer, sectors_in_cluster, bytes_per_sector) = unsafe {
            let disk_name = to_pcwstr(&disk_path[..]);
            let disk_pointer = match CreateFileW(
                PCWSTR::from_raw(disk_name.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            ) {
                Ok(v) => v,
                Err(e) => {
                    panic!("Error {:?}", e);
                }
            };
            let mut sectors_in_cluster = 0;
            let mut bytes_per_sector = 0;
            let mut free_clusters = 0;
            let mut total_clusters = 0;

            let disk_name = to_pcwstr(&&disk_letter[..]);
            if !GetDiskFreeSpaceW(
                PCWSTR::from_raw(disk_name.as_ptr()),
                Some(&mut sectors_in_cluster),
                Some(&mut bytes_per_sector),
                Some(&mut free_clusters),
                Some(&mut total_clusters),
            )
            .as_bool()
            {
                return Err(ForensicError::Other(format!(
                    "Cannot retrieve Disk Info: {}",
                    GetLastError()
                )));
            }
            (disk_pointer, sectors_in_cluster, bytes_per_sector)
        };

        let file_pointer = unsafe {
            let filename = format!("\\\\.\\{}\0", pth);
            match CreateFileW(
                PCWSTR::from_raw(to_pcwstr(&filename[..]).as_ptr()),
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_MODE(FILE_SHARE_READ.0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            ) {
                Ok(v) => v,
                Err(e) => {
                    return Err(ForensicError::Other(format!("{}", e.message())));
                }
            }
        };
        let file_size = unsafe {
            let mut file_size_high = 0;
            let file_size_low = GetFileSize(file_pointer, Some(&mut file_size_high));
            let file_size = ((file_size_high as u64) << 32) | (file_size_low as u64);
            file_size
        };

        let buffer_size: u32 = 10_000;
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
        let ret_pointers = unsafe {
            let mut in_buffer = STARTING_VCN_INPUT_BUFFER::default();

            // RETRIEVAL_POINTERS_BUFFER
            let mut bytes_returned = 0;
            if DeviceIoControl(
                file_pointer,
                FSCTL_GET_RETRIEVAL_POINTERS,
                Some(std::ptr::addr_of_mut!(in_buffer) as _),
                std::mem::size_of::<STARTING_VCN_INPUT_BUFFER>() as u32,
                Some(buffer.as_mut_ptr() as _),
                buffer_size,
                Some(&mut bytes_returned),
                None,
            )
            .as_bool()
            {
                let ret_point = buffer_to_retrieval_pointers(&buffer[0..bytes_returned as usize]);
                ret_point
            } else {
                return Err(ForensicError::Other(format!("Cannot retrive FSCTL pointers, error={}, file: {}",GetLastError(), pth)));
            }
        };
        Ok(RawFile {
            disk_pointer,
            file_size,
            ret_pointers,
            buffer_for_cluster: (bytes_per_sector * sectors_in_cluster) as usize,
            extent_i: 0,
            readed_bytes: 0,
            cluster_i: 0,
        })
    }

    pub fn copy_to<P: AsRef<Path>>(&self, pth: P) -> ForensicResult<()> {
        let path = pth.as_ref();
        let pth = match path.to_str() {
            Some(v) => v,
            None => return Err(ForensicError::Missing),
        };
        let mut file_cloned = RawFile {
            buffer_for_cluster: self.buffer_for_cluster,
            cluster_i: 0,
            extent_i: 0,
            file_size: self.file_size,
            disk_pointer: self.disk_pointer,
            readed_bytes: 0,
            ret_pointers: self.ret_pointers.clone(),
        };

        let mut buffer = vec![0u8; self.buffer_for_cluster * 16];
        let file = std::fs::File::create(&pth)?;
        let mut file = std::io::BufWriter::new(file);
        loop {
            let readed = file_cloned.read(&mut buffer)?;
            if readed == 0 {
                break;
            }
            file.write_all(&mut buffer[0..readed])?;
        }
        Ok(())
    }
}

impl std::io::Read for RawFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.len() < self.buffer_for_cluster {
            return Err(std::io::Error::from_raw_os_error(
                ERROR_INSUFFICIENT_BUFFER.0 as i32,
            ));
        }
        if self.readed_bytes >= self.file_size as usize {
            return Ok(0);
        }
        if self.extent_i > self.ret_pointers.extent_count as usize {
            return Ok(0);
        }
        let clusters_to_read = buf.len() / self.buffer_for_cluster;
        let bytes_fit_in_buffer = (clusters_to_read * self.buffer_for_cluster) as u32;

        let last_vcn = if self.extent_i > 0 {
            self.ret_pointers.extents[self.extent_i - 1].next_vcn
        } else {
            self.ret_pointers.starting_vcn
        };
        let extent: &PointerExtent = &self.ret_pointers.extents[self.extent_i];
        let cluster_length = ((extent.next_vcn - last_vcn) as u64) * self.buffer_for_cluster as u64;
        let disk_offset = (extent.lcn + self.cluster_i as i64) * self.buffer_for_cluster as i64;
        let cluster_offset = self.cluster_i as i64 * self.buffer_for_cluster as i64;
        // Move disk position
        unsafe {
            if !SetFilePointerEx(self.disk_pointer, disk_offset, None, FILE_BEGIN).as_bool() {
                return Err(std::io::Error::from_raw_os_error(GetLastError() as i32));
            }
        }
        //Read disk
        let mut readed_bytes = 0;
        let bytest_to_read_from_disk: u32 =
            if (cluster_length - cluster_offset as u64) < bytes_fit_in_buffer.into() {
                (cluster_length - cluster_offset as u64) as u32
            } else {
                bytes_fit_in_buffer
            };
        unsafe {
            if !ReadFile(
                self.disk_pointer,
                Some(buf.as_mut_ptr() as _),
                bytest_to_read_from_disk,
                Some(&mut readed_bytes),
                None,
            )
            .as_bool()
            {
                return Err(std::io::Error::from_raw_os_error(GetLastError() as i32));
            }
        }
        if (self.readed_bytes + readed_bytes as usize) > self.file_size as usize {
            readed_bytes = (self.file_size - self.readed_bytes as u64) as u32;
        }
        self.readed_bytes += readed_bytes as usize;
        if (self.cluster_i + clusters_to_read) >= (extent.next_vcn as usize - last_vcn as usize) {
            // Move cluster and extent
            self.extent_i += 1;
            self.cluster_i = 0;
        } else {
            self.cluster_i += clusters_to_read;
        }

        Ok(readed_bytes as usize)
    }
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

#[cfg(test)]
mod tst {
    use std::io::{Read, Write};
    use std::path::PathBuf;

    fn test_file_name() -> PathBuf {
        std::env::temp_dir().join("ones_file_ftrnsc_triage.dat")
    }

    fn generate_file_full_of_ones() {
        let file_path = test_file_name();
        if file_path.exists() {
            return;
        }
        let mut file = std::fs::File::create(&file_path).unwrap();
        let buff = vec![0xffu8; 4096];
        for _ in 0..1024 {
            file.write_all(&buff).unwrap();
        }
    }

    #[test]
    fn etc_hosts() {
        let mut file = super::RawFile::open(r#"C:\Windows\System32\drivers\etc\hosts"#).unwrap();
        let mut buff = vec![0; 13_000];
        let readed = file.read(&mut buff).unwrap();
        println!("{}", String::from_utf8_lossy(&buff[0..readed]));
    }

    #[test]
    fn mft() {
        let file = super::RawFile::open(r#"C:\$MFT"#).unwrap();
        let destination = std::env::temp_dir().join("test-mft");
        file.copy_to(destination).unwrap();
    }

    #[test]
    fn file_full_of_ones_can_be_fully_readed_and_copied() {
        generate_file_full_of_ones();
        let filename = test_file_name();
        let mut file = super::RawFile::open(&filename).unwrap();
        let mut buff = vec![0; 13_000];
        let mut total_readed = 0;
        loop {
            let readed = file.read(&mut buff).unwrap();
            if readed == 0 {
                break;
            }
            total_readed += readed;
            assert!((buff.len() / file.buffer_for_cluster) * file.buffer_for_cluster >= readed);
            let mut pos = 0;
            for i in &buff[0..readed] {
                if *i != 0xff {
                    panic!("buff[{}]={}!=255, readed={}", pos, i, readed);
                }
                pos += 1;
            }
        }
        assert_eq!(4096 * 1024, total_readed);
        let copied_file_path = std::env::temp_dir().join("copied_ones_file_ftrnsc_triage.dat");
        file.copy_to(&copied_file_path).unwrap();

        let mut copied_file = std::fs::File::open(copied_file_path).unwrap();
        let mut buffer = vec![0; 4096];
        total_readed = 0;
        let mut pos = 0;
        loop {
            let readed = copied_file.read(&mut buffer).unwrap();
            if readed == 0 {
                break;
            }
            total_readed += readed;
            for i in &buff[0..readed] {
                if *i != 0xff {
                    panic!("buff[{}]={}!=255, readed={}", pos, i, readed);
                }
                pos += 1;
            }
        }
        assert_eq!(4096 * 1024, total_readed);
    }
}