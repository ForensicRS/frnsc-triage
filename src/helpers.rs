pub fn replace_envvars(txt: &str, system_drive : &str, system_root : &str, prog_data : &str) -> String {
    let pos = match txt[..].find(r"%\") {
        Some(pos) => pos,
        None => return txt.to_string()
    };

    let variable = &txt[1..pos];
    if is_system_drive_env(variable) {
        return if system_drive.ends_with(r"\") {
            format!(r"{}{}",system_drive, &txt[pos + 2..])
        }else {
            format!(r"{}\{}",system_drive,&txt[pos + 2..])
        };
    }else if is_system_root_env(variable) {
        return if system_root.ends_with(r"\") {
            format!(r"{}{}",system_root, &txt[pos + 2..])
        }else {
            format!(r"{}\{}",system_root,&txt[pos + 2..])
        };
    }else if is_program_data_env(variable) {
        return if prog_data.ends_with(r"\") {
            format!(r"{}{}",prog_data, &txt[pos + 2..])
        }else {
            format!(r"{}\{}",prog_data,&txt[pos + 2..])
        };
    }
    txt.to_string()
}

pub fn replace_home_vars(txt: &str, homes : &Vec<String>) -> Vec<String> {
    let pos = match txt[..].find(r"%\") {
        Some(pos) => pos,
        None => return vec![]
    };

    let variable = &txt[1..pos];
    let mut to_ret = Vec::with_capacity(32);
    for home in homes {
        if home.ends_with(r"\") {
            to_ret.push(format!(r"{}{}",home, &txt[pos + 2..]));
        }else {
            to_ret.push(format!(r"{}\{}",home, &txt[pos + 2..]));
        }
    }
    to_ret
}


pub fn contains_env_var(txt : &str) -> bool {
    txt.starts_with("%")
}


pub fn is_system_drive_env(txt : &str) -> bool {
    if txt.len() != "systemdrive".len() {
        return false
    }
    txt.to_uppercase() == "SYSTEMDRIVE"
}
pub fn is_system_root_env(txt : &str) -> bool {
    if txt.len() != "systemroot".len() {
        return false
    }
    txt.to_uppercase() == "SYSTEMROOT"
}
pub fn is_program_data_env(txt : &str) -> bool {
    if txt.len() != "programdata".len() {
        return false
    }
    txt.to_uppercase() == "PROGRAMDATA"
}

pub fn is_user_home_env(txt : &str) -> bool {
    txt.starts_with("%USERHOME%")
}
