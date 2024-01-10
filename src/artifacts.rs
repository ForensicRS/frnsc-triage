
pub const USN_JRNL_PATH : &'static str = r"%SYSTEMDRIVE%\$Extend\$UsnJrnl:$J";
pub const USN_JRNL_MAX_PATH : &'static str = r"%SYSTEMDRIVE%\$Extend\$UsnJrnl:$MAX";

pub fn get_default_collection_paths() -> Vec<String> {
    let mut vc = Vec::with_capacity(1_000);
    DEFAULT_COLLECTION_PATHS.iter().for_each(|v| vc.push(v.to_string()));
    vc
}

pub const DEFAULT_COLLECTION_PATHS : [&'static str; 42] = [
    r"%SYSTEMDRIVE%\$LogFile",
    r"%SYSTEMDRIVE%\$MFT",
    r"%SYSTEMROOT%\Tasks\**",
    r"%SYSTEMROOT%\Prefetch\**",
    r"%SYSTEMROOT%\System32\sru\**",
    r"%SYSTEMROOT%\System32\winevt\Logs\**",
    r"%SYSTEMROOT%\System32\Tasks\**",
    r"%SYSTEMROOT%\System32\Logfiles\W3SVC1\**",
    r"%SYSTEMROOT%\System32\drivers\etc\hosts",
    r"%SYSTEMROOT%\System32\config\SAM",
    r"%SYSTEMROOT%\System32\config\SYSTEM",
    r"%SYSTEMROOT%\System32\config\SECURITY",
    r"%SYSTEMROOT%\System32\config\SOFTWARE",
    r"%SYSTEMROOT%\System32\config\SAM.LOG1",
    r"%SYSTEMROOT%\System32\config\SYSTEM.LOG1",
    r"%SYSTEMROOT%\System32\config\SECURITY.LOG1",
    r"%SYSTEMROOT%\System32\config\SOFTWARE.LOG1",
    r"%SYSTEMROOT%\System32\config\SAM.LOG2",
    r"%SYSTEMROOT%\System32\config\SYSTEM.LOG2",
    r"%SYSTEMROOT%\System32\config\SECURITY.LOG2",
    r"%SYSTEMROOT%\System32\config\SOFTWARE.LOG2",
    r"%SYSTEMROOT%\System32\LogFiles\SUM\**",
    r"%SYSTEMROOT%\Appcompat\Programs\**",
    r"%SYSTEMROOT%\SchedLgU.txt",
    r"%SYSTEMROOT%\inf\setupapi.dev.log",
    r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup\**",
    r"%SYSTEMDRIVE%\$Recycle.Bin\**\$I*",
    r"%SYSTEMDRIVE%\$Recycle.Bin\$I*",
    r"%USERHOME%\NTUser.DAT",
    r"%USERHOME%\NTUser.DAT.LOG1",
    r"%USERHOME%\NTUser.DAT.LOG2",
    r"%USERHOME%\AppData\Roaming\Microsoft\Windows\Recent\**",
    r"%USERHOME%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
    r"%USERHOME%\AppData\Roaming\Mozilla\Firefox\Profiles\**",
    r"%USERHOME%\AppData\Local\Microsoft\Windows\WebCache\**",
    r"%USERHOME%\AppData\Local\Microsoft\Windows\Explorer\**",
    r"%USERHOME%\AppData\Local\Microsoft\Windows\UsrClass.dat",
    r"%USERHOME%\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1",
    r"%USERHOME%\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2",
    r"%USERHOME%\AppData\Local\ConnectedDevicesPlatform\**",
    r"%USERHOME%\AppData\Local\Google\Chrome\User Data\Default\History\**",
    r"%USERHOME%\AppData\Local\Microsoft\Edge\User Data\Default\History\**",
];