use forensic_rs::prelude::{ForensicError, ForensicResult};
use std::io::{Read, Write};
use std::path::Path;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};

use crate::helpers::{get_drive_metadata, get_file_pointer_and_size, get_retrieval_pointers, move_disk_position, read_file_from_disk_pointer, Buffer, PointerExtent, RetrievalPointersBuffer};

pub struct RawFile {
    pub disk_pointer: HANDLE,
    pub file_size: u64,
    pub ret_pointers: RetrievalPointersBuffer,
    pub buffer_for_cluster: usize,
    pub extent_i: usize,
    pub readed_bytes: usize,
    pub cluster_i: usize,
    pub buffer : Buffer
}

impl RawFile {
    pub fn open<P: AsRef<Path>>(path: P) -> ForensicResult<Self> {
        let path = path.as_ref();
        let pth = match path.to_str() {
            Some(v) => v,
            None => return Err(ForensicError::missing_str("Cannot cast Path to &str")),
        };
        let mut buffer = Buffer::with_capacity(32_000);
        let (disk_pointer, sectors_in_cluster, bytes_per_sector) = get_drive_metadata(&pth, &mut buffer)?;
        let (file_pointer, file_size) = get_file_pointer_and_size(pth, &mut buffer)?;
        let ret_pointers = get_retrieval_pointers(file_pointer, &mut buffer)?;
        buffer.reset();
        Ok(RawFile {
            disk_pointer,
            file_size,
            ret_pointers,
            buffer_for_cluster: (bytes_per_sector * sectors_in_cluster) as usize,
            extent_i: 0,
            readed_bytes: 0,
            cluster_i: 0,
            buffer
        })
    }

    pub fn copy_to<P: AsRef<Path>>(&self, pth: P) -> ForensicResult<()> {
        let path = pth.as_ref();
        let pth = match path.to_str() {
            Some(v) => v,
            None => return Err(ForensicError::missing_str("Cannot cast Path to &str")),
        };
        let mut file_cloned = RawFile {
            buffer_for_cluster: self.buffer_for_cluster,
            cluster_i: 0,
            extent_i: 0,
            file_size: self.file_size,
            disk_pointer: self.disk_pointer,
            readed_bytes: 0,
            ret_pointers: self.ret_pointers.clone(),
            buffer : Buffer::new()
        };
        let mut buffer = Buffer::with_capacity(self.buffer_for_cluster * 16);
        let buff = buffer.u8();
        let file = std::fs::File::create(&pth)?;
        let mut file = std::io::BufWriter::new(file);
        loop {
            let readed = file_cloned.read(buff)?;
            if readed == 0 {
                break;
            }
            file.write_all(&mut buff[0..readed])?;
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
        let last_vcn = if self.extent_i > 0 {
            self.ret_pointers.extents[self.extent_i - 1].next_vcn
        } else {
            self.ret_pointers.starting_vcn
        };
        let extent: &PointerExtent = &self.ret_pointers.extents[self.extent_i];
        let disk_offset = (extent.lcn + self.cluster_i as i64) * self.buffer_for_cluster as i64;
        // Move disk position
        move_disk_position(self.disk_pointer, disk_offset)?;
        //Read disk
        let cluster_length = ((extent.next_vcn - last_vcn) as u64) * self.buffer_for_cluster as u64;
        let cluster_offset = self.cluster_i as i64 * self.buffer_for_cluster as i64;
        let bytes_fit_in_buffer = (clusters_to_read * self.buffer_for_cluster) as u64;
        let bytes_to_be_readed = if (cluster_length - cluster_offset as u64) < bytes_fit_in_buffer {
            (cluster_length - cluster_offset as u64) as u32
        }else {
            bytes_fit_in_buffer as u32
        };
        let mut readed_bytes = read_file_from_disk_pointer(self.disk_pointer, buf, bytes_to_be_readed)?;
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
    fn am_cache() {
        let file = super::RawFile::open(r#"C:\Windows\AppCompat\Programs\Amcache.hve"#).unwrap();
        let destination = std::env::temp_dir().join("Amcache-test.hve");
        file.copy_to(destination).unwrap();
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