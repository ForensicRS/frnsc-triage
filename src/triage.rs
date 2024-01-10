use std::{
    collections::{BTreeMap, BTreeSet},
    fs::ReadDir,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    artifacts::{get_default_collection_paths, USN_JRNL_MAX_PATH, USN_JRNL_PATH},
    helpers::{contains_env_var, is_user_home_env, replace_envvars, replace_home_vars},
    raw_file::RawFile,
    sys_vars::{
        list_users_homes_from_reg, mounted_devices, program_data, system_drive, system_root,
    },
};
use forensic_rs::{prelude::ForensicResult, traits::registry::RegistryReader};
use frnsc_liveregistry_rs::LiveRegistryReader;
use regex::Regex;
use zip::{write::FileOptions, DateTime};

pub struct TriageCollector {
    params: CollectionParameters,
}

#[derive(Clone, Debug)]
pub struct CollectionParameters {
    /// Collects the MFT from all disks
    pub all_disks_mft: bool,
    /// Collects the USN journal from the system drive
    pub usn_jrnl: bool,
    /// Collects the USN journal for all the drives
    pub all_usn_jrnl: bool,
    pub paths: Vec<String>,
    pub out_file: String,
    pub threads: usize,
    pub buffer_size: usize,
}

impl Default for CollectionParameters {
    fn default() -> Self {
        Self {
            all_disks_mft: false,
            usn_jrnl: false,
            all_usn_jrnl: false,
            paths: get_default_collection_paths(),
            out_file: "./frnsc-triage.zip".to_string(),
            threads: 4,
            buffer_size: 1_000_000,
        }
    }
}

impl TriageCollector {
    pub fn new(params: CollectionParameters) -> Self {
        Self { params }
    }

    pub fn collect(&self) -> ForensicResult<()> {
        let paths_to_process = self.prepare_paths_to_collect();
        let mutex = Arc::new(Mutex::new(paths_to_process));
        let zip_file = std::fs::File::create(&self.params.out_file)?;
        let shared_zip = Arc::new(Mutex::new(zip::ZipWriter::new(zip_file)));

        let mut thread_handlers = Vec::with_capacity(self.params.threads);
        let buffer_size = self.params.buffer_size;
        for i in 0..self.params.threads {
            let shared_zip = shared_zip.clone();
            let paths_to_process = Arc::clone(&mutex);
            thread_handlers.push(
                std::thread::Builder::new()
                    .name(format!("TriageThrd{}", i))
                    .spawn(move || {
                        // 1 MB buffer
                        let mut buffer = vec![0; buffer_size];
                        loop {
                            let path_to_file = match paths_to_process.as_ref().lock() {
                                Ok(mut v) => match v.pop() {
                                    Some(v) => v,
                                    None => return,
                                },
                                Err(_) => todo!(),
                            };
                            let zip_path_to_file = path_to_file.replace(":\\", "\\");
                            let splited_path: Vec<String> = path_to_file
                                .split(std::path::MAIN_SEPARATOR)
                                .into_iter()
                                .map(|v| v.to_string())
                                .collect();
                            if path_to_file.contains("*") {
                                for pth in zip_path_to_file.split(std::path::MAIN_SEPARATOR) {
                                    if pth == "*" {
                                    } else if pth == "**" {
                                    } else {
                                    }
                                }
                                continue;
                            }
                            let parent_folder = std::path::Path::new(&path_to_file).parent();

                            let mut file = match RawFile::open(&path_to_file) {
                                Ok(v) => v,
                                Err(_) => {
                                    println!("Error processing {}", path_to_file);
                                    continue;
                                }
                            };
                            if (file.file_size as usize) < buffer.len() {
                                let readed = match file.read(&mut buffer) {
                                    Ok(v) => v,
                                    Err(_) => continue,
                                };
                                if file.file_size as usize != readed {
                                    continue;
                                }
                                let mut zip_guard = shared_zip.lock().unwrap();
                                if let Some(parent) = parent_folder {
                                    let ancstr = parent.to_str().unwrap().replace(":\\", "\\");
                                    match zip_guard.add_directory(
                                        &ancstr,
                                        FileOptions::default()
                                            .compression_level(Some(6))
                                            .compression_method(zip::CompressionMethod::Deflated),
                                    ) {
                                        Ok(_) => {
                                            println!("Creating ancestors {}", &ancstr);
                                        }
                                        Err(err) => {
                                            println!(
                                                "Error Creating directory {}: {:?}",
                                                &ancstr, err
                                            )
                                        }
                                    }
                                }
                                match zip_guard.start_file(
                                    &path_to_file.replace(":\\", "\\"),
                                    FileOptions::default()
                                        .compression_level(Some(6))
                                        .compression_method(zip::CompressionMethod::Deflated),
                                ) {
                                    Ok(_) => {
                                        println!("Creating file {}", &path_to_file);
                                    }
                                    Err(err) => {
                                        println!("Error Creating file {}: {:?}", &path_to_file, err)
                                    }
                                }

                                let _ = zip_guard.write_all(&buffer[0..readed]);
                            } else {
                                let mut zip_guard = shared_zip.lock().unwrap();
                                if let Some(parent) = parent_folder {
                                    let ancstr = parent.to_str().unwrap().replace(":\\", "\\");
                                    match zip_guard.add_directory(
                                        &ancstr,
                                        FileOptions::default()
                                            .compression_level(Some(6))
                                            .compression_method(zip::CompressionMethod::Deflated),
                                    ) {
                                        Ok(_) => {
                                            println!("Creating ancestors {}", &ancstr);
                                        }
                                        Err(err) => {
                                            println!(
                                                "Error Creating directory {}: {:?}",
                                                &ancstr, err
                                            )
                                        }
                                    }
                                }
                                match zip_guard.start_file(
                                    &path_to_file.replace(":\\", "\\"),
                                    FileOptions::default()
                                        .compression_level(Some(6))
                                        .compression_method(zip::CompressionMethod::Deflated),
                                ) {
                                    Ok(_) => {
                                        println!("Creating file {}", &path_to_file);
                                    }
                                    Err(err) => {
                                        println!("Error Creating file {}: {:?}", &path_to_file, err)
                                    }
                                }
                                loop {
                                    let readed = match file.read(&mut buffer) {
                                        Ok(v) => v,
                                        Err(_) => continue,
                                    };
                                    if readed == 0 {
                                        break;
                                    }
                                    let _ = zip_guard.write_all(&buffer[0..readed]);
                                }
                            }
                            println!("Processing: {}, file_size={}", path_to_file, file.file_size);
                        }
                    })
                    .unwrap(),
            );
        }

        for thread in thread_handlers {
            thread.join().unwrap();
        }

        Ok(())
    }

    fn prepare_paths_to_collect(&self) -> Vec<String> {
        let registry = LiveRegistryReader::new();
        let mut to_ret = Vec::with_capacity(1_000);
        let mut registry: Box<dyn RegistryReader> = Box::new(registry);
        let sys_root = system_root(&mut registry);
        let sys_drive = system_drive(&mut registry);
        let prog_data = replace_envvars(&program_data(&mut registry), &sys_drive, &sys_root, "");
        let users_homes = match list_users_homes_from_reg(&mut registry) {
            Ok(pths) => {
                let mut vc = Vec::with_capacity(32);
                for v in pths {
                    if contains_env_var(&v) {
                        vc.push(replace_envvars(&v, &sys_root, &sys_drive, &prog_data));
                    } else {
                        vc.push(v);
                    }
                }
                vc
            }
            Err(_) => vec![],
        };

        if self.params.usn_jrnl {
            to_ret.push(replace_envvars(
                USN_JRNL_PATH,
                &sys_drive,
                &sys_root,
                &prog_data,
            ));
            to_ret.push(replace_envvars(
                USN_JRNL_MAX_PATH,
                &sys_drive,
                &sys_root,
                &prog_data,
            ));
        }
        let mounted_devices = mounted_devices();
        if self.params.all_disks_mft {
            for device in &mounted_devices {
                if device == &sys_drive {
                    continue;
                }
                let mft_path = format!("{}$MFT", device);
                to_ret.push(mft_path);
            }
        }
        if self.params.all_usn_jrnl {
            for device in &mounted_devices {
                if device == &sys_drive && self.params.usn_jrnl {
                    continue;
                }
                to_ret.push(format!(r"{}\$Extend\$UsnJrnl:$J", device));
                to_ret.push(format!(r"{}\$Extend\$UsnJrnl:$MAX", device));
            }
        }

        for path in &self.params.paths {
            if is_user_home_env(&path) {
                for pth in replace_home_vars(path, &users_homes) {
                    to_ret.push(pth);
                }
            } else if contains_env_var(path) {
                to_ret.push(replace_envvars(path, &sys_drive, &sys_root, &prog_data));
            } else {
                to_ret.push(path.to_string());
            }
        }

        to_ret
    }
}


#[derive(Debug)]
struct EndPathPattern {
    pattern: String,
    base_path: PathBuf,
    fs_iter: Option<ReadDir>,
    path_pattern: Option<Box<EndPathPattern>>,
}

impl EndPathPattern {
    pub fn new(pattern: String) -> Result<Self, std::io::Error> {
        let (pattern, base_path) = match pattern.rfind("\\") {
            Some(pos) => (pattern[pos + 1..].to_string(),pattern[..pos].to_string()),
            None => (format!(".*"), pattern.clone())
        };
        let fs_iter = if std::path::Path::new(&base_path).is_dir() {
            Some(std::fs::read_dir(&base_path)?)
        } else {
            None
        };
        Ok(EndPathPattern {
            pattern,
            base_path : std::path::PathBuf::from(base_path),
            fs_iter,
            path_pattern : None
        })
    }
}

impl PathPatternIterator for EndPathPattern {}

impl Iterator for EndPathPattern {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(pth_pattrn) = &mut self.path_pattern {
                let nxt = pth_pattrn.next();
                if let Some(nxt_elmnt) = nxt {
                    return Some(nxt_elmnt);
                }
            }
            self.path_pattern = None;
            if let Some(readdir) = &mut self.fs_iter {
                match readdir.next() {
                    Some(v) => match v {
                        Ok(dir_entry) => match dir_entry.file_type() {
                            Ok(v) => {
                                if v.is_dir() {
                                    let pth = dir_entry.path().to_str().unwrap_or("").to_string();
                                    if self.pattern == "**" {
                                        match EndPathPattern::new(format!("{}\\{}", pth, self.pattern)) {
                                            Ok(v) => {
                                                self.path_pattern = Some(Box::new(v));
                                            }
                                            Err(err) => {
                                                println!("Error creating base pattern: {:?} {} {:?}", dir_entry.path(), self.pattern, err);
                                            }
                                        };
                                    }
                                    continue;
                                } else if v.is_file() {
                                    let pth = dir_entry.path().to_str().unwrap_or("").to_string();
                                    if pth.is_empty() {
                                        continue;
                                    }
                                    match Regex::new(&replace_pattern(&self.pattern)) {
                                        Ok(v) => {
                                            if v.find(&pth).is_some() {
                                                return Some(pth);
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                    
                                }
                            }
                            Err(_) => {}
                        },
                        Err(_) => {}
                    },
                    None => {
                        break;
                    }
                }
            }
        }
        None
    }
}

struct PathPattern {
    pattern: String,
    base_path: PathBuf,
    first_pattern : String,
    last_pattern : String,
    path_pattern: Option<Box<dyn PathPatternIterator>>,
    fs_iter: Option<ReadDir>,
}

impl PathPattern {
    pub fn with_base(base_path: PathBuf, pattern: String) -> Result<Self, std::io::Error> {
        let (first_pattern, last_pattern) = match pattern.find("\\") {
            Some(p) => (pattern[..p].to_string(), pattern[p+1..].to_string()),
            None => (pattern.clone(), format!("*"))
        };
        
        let fs_iter = if base_path.is_dir() {
            Some(std::fs::read_dir(&base_path)?)
        } else {
            None
        };

        Ok(Self {
            pattern,
            base_path,
            first_pattern,
            last_pattern,
            path_pattern: None,
            fs_iter,
        })
    }

    pub fn new(pattern: String) -> Result<Self, std::io::Error> {
        let split_pth: Vec<String> = pattern
            .split(std::path::MAIN_SEPARATOR)
            .into_iter()
            .map(|v| v.to_string())
            .collect();
        let mut pos = 0;
        for elmnt in &split_pth {
            if elmnt.contains("*") {
                break;
            }
            pos += 1;
        }
        let base_path = split_pth[0..pos].join("\\");
        let pattern = split_pth[pos..].join("\\");
        Self::with_base(PathBuf::from(base_path), pattern)
    }
}

pub trait PathPatternIterator : Iterator<Item = String>{
    fn next_path(&mut self) -> Option<String> {
        self.next()
    }
}

impl PathPatternIterator for PathPattern {}

impl Iterator for PathPattern {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(pth_pattrn) = &mut self.path_pattern {
                let nxt = pth_pattrn.next();
                if let Some(nxt_elmnt) = nxt {
                    return Some(nxt_elmnt);
                }
            }
            self.path_pattern = None;
            if let Some(readdir) = &mut self.fs_iter {
                match readdir.next() {
                    Some(v) => match v {
                        Ok(dir_entry) => match dir_entry.file_type() {
                            Ok(v) => {
                                if v.is_dir() {
                                    match PathPattern::with_base(dir_entry.path(), self.last_pattern.clone()) {
                                        Ok(v) => {
                                            self.path_pattern = Some(Box::new(v));
                                        }
                                        Err(err) => {
                                            println!("Error creating base pattern: {:?} {} {:?}", dir_entry.path(), self.pattern, err);
                                        }
                                    };
                                    continue;
                                } else if v.is_file() {
                                    let pth = dir_entry.path().to_str().unwrap_or("").to_string();
                                    if pth.is_empty() {
                                        continue;
                                    }
                                    match Regex::new(&replace_pattern(&self.last_pattern)) {
                                        Ok(v) => {
                                            if v.find(&pth).is_some() {
                                                return Some(pth);
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                    
                                }
                            }
                            Err(_) => {}
                        },
                        Err(_) => {}
                    },
                    None => {
                        break;
                    }
                }
            }
        }
        if self.base_path.ancestors().next().is_none() {
            return None;
        }
        let mut new_str = PathBuf::new();
        std::mem::swap(&mut self.base_path, &mut new_str);
        let pth = new_str.to_str().unwrap_or("").to_string();
        if pth.trim().is_empty() {
            return None
        }
        match Regex::new(&replace_pattern(&self.last_pattern)) {
            Ok(v) => {
                if v.find(&pth).is_some() {
                    return Some(pth);
                }
            }
            Err(_) => {}
        }
        None
    }
}

pub fn replace_pattern(ptrn : &str) -> String {
    format!("^{}$",ptrn.replace(".", "\\.").replace("*", ".*").replace(".*.*",".*"))
}

#[test]
fn test_collector() {
    let out_file = std::env::temp_dir().join("triage-test.zip").as_os_str().to_string_lossy().into_owned();
    let collector = TriageCollector::new(CollectionParameters {
        all_disks_mft: false,
        usn_jrnl: false,
        all_usn_jrnl: false,
        paths: get_default_collection_paths(),
        out_file,
        threads: 4,
        buffer_size: 1_000_000,
    });
    collector.collect().expect("Should generate ZIP file");
}

#[test]
fn pattern_should_print_all() {
    let pattern = EndPathPattern::new(format!(r"C:\Windows\Tasks\**")).unwrap();
    for element in pattern.into_iter() {
        println!("{}", element);
    }

    

    let pattern = PathPattern::new(format!(r"C:\Windows\**\*.exe")).unwrap();
    for element in pattern.into_iter() {
        println!("{}", element);
    }
    panic!("");
    let pattern = EndPathPattern::new(format!(r"C:\Windows\**")).unwrap();
    for element in pattern.into_iter() {
        println!("{}", element);
    }
}
