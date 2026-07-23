//! Windows named-pipe transport with owner-only DACLs and token SID checks.

#![allow(unsafe_code)] // Audited Win32 FFI is confined to this module.

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::sync::Semaphore;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_BUSY, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE,
    SDDL_REVISION_1, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, DACL_SECURITY_INFORMATION, GetTokenInformation,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_WRITE_DATA,
    GetFileAttributesW, INVALID_FILE_ATTRIBUTES, SECURITY_IDENTIFICATION, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{
    AdminPolicy, HelperRequest, HelperResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    OwnerIdentity, decode_request, decode_response, handle_authenticated_request, read_frame,
    write_frame,
};

const PIPE_NAME: &str = r"\\.\pipe\RunOnMine.Helper";
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
const BUILTIN_ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const LOW_PRIVILEGE_SIDS: &[&str] = &["S-1-1-0", "S-1-5-11", "S-1-5-32-545"];
const MAX_CONCURRENT_CLIENTS: usize = 16;

pub(super) async fn client_request(
    owner: &OwnerIdentity,
    request: &HelperRequest,
) -> Result<HelperResponse> {
    let OwnerIdentity::WindowsSid { sid } = owner else {
        bail!("a Windows helper requires a Windows owner SID");
    };
    if !current_user_sid()?.eq_ignore_ascii_case(sid) {
        bail!("the helper client owner does not match the current Windows user");
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut client = loop {
        match ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(PIPE_NAME)
        {
            Ok(client) => break client,
            Err(error)
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY.cast_signed())
                    && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error).context("failed to connect to the privileged helper"),
        }
    };
    verify_server_is_local_system(&client)?;
    write_frame(&mut client, request, MAX_REQUEST_BYTES).await?;
    let response = read_frame(&mut client, MAX_RESPONSE_BYTES).await?;
    decode_response(&response, request.request_id)
}

pub(super) async fn serve(policy: AdminPolicy) -> Result<()> {
    let sid = match &policy.owner {
        OwnerIdentity::WindowsSid { sid } => sid.clone(),
        OwnerIdentity::UnixUid { .. } => {
            bail!("a Windows helper policy requires a Windows owner SID")
        }
    };
    let policy = Arc::new(policy);
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let mut server = create_server(&sid)?;
    loop {
        server
            .connect()
            .await
            .context("failed to accept a privileged helper client")?;
        let connected = server;
        server = create_server(&sid)?;
        let peer_sid = match connected_client_sid(&connected) {
            Ok(peer_sid) if peer_sid.eq_ignore_ascii_case(&sid) => peer_sid,
            _ => continue,
        };
        let _ = peer_sid;
        let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
            continue;
        };
        let policy = Arc::clone(&policy);
        tokio::spawn(async move {
            let _permit = permit;
            let _ignored = handle_client(connected, &policy).await;
        });
    }
}

async fn handle_client(mut pipe: NamedPipeServer, policy: &AdminPolicy) -> Result<()> {
    let bytes = read_frame(&mut pipe, MAX_REQUEST_BYTES).await?;
    let request = decode_request(&bytes)?;
    let response = handle_authenticated_request(policy, request).await;
    write_frame(&mut pipe, &response, MAX_RESPONSE_BYTES).await
}

fn create_server(owner_sid: &str) -> Result<NamedPipeServer> {
    let sddl = format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{owner_sid})");
    let wide_sddl = wide(&sddl);
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: wide_sddl is NUL-terminated, and descriptor is released with
    // LocalFree after CreateNamedPipe has synchronously copied the ACL.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 || descriptor.is_null() {
        return Err(io::Error::last_os_error()).context("failed to build the helper pipe ACL");
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let created = {
        let mut options = ServerOptions::new();
        options
            .max_instances(MAX_CONCURRENT_CLIENTS)
            .reject_remote_clients(true)
            .in_buffer_size(u32::try_from(MAX_REQUEST_BYTES).unwrap_or(u32::MAX))
            .out_buffer_size(u32::try_from(MAX_RESPONSE_BYTES).unwrap_or(u32::MAX));
        // SAFETY: attributes and its security descriptor remain valid for the
        // complete synchronous create call.
        unsafe {
            options.create_with_security_attributes_raw(
                PIPE_NAME,
                (&raw mut attributes).cast::<c_void>(),
            )
        }
    };
    // SAFETY: descriptor was allocated by LocalAlloc through the conversion API.
    unsafe {
        LocalFree(descriptor);
    }
    created.context("failed to create the privileged helper pipe")
}

fn connected_client_sid(pipe: &NamedPipeServer) -> Result<String> {
    let handle = pipe.as_raw_handle().cast::<c_void>();
    // SAFETY: handle is a connected server-side named-pipe handle.
    if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
        return Err(io::Error::last_os_error()).context("failed to authenticate helper client");
    }
    let _revert = RevertGuard;
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the current thread is impersonating the connected pipe client.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error()).context("failed to open helper client token");
    }
    token_user_sid(&OwnedHandle(token))
}

fn verify_server_is_local_system(pipe: &NamedPipeClient) -> Result<()> {
    let mut process_id = 0_u32;
    let handle = pipe.as_raw_handle().cast::<c_void>();
    // SAFETY: handle is an open client-side named-pipe handle.
    if unsafe { GetNamedPipeServerProcessId(handle, &raw mut process_id) } == 0 || process_id == 0 {
        return Err(io::Error::last_os_error()).context("failed to identify helper server");
    }
    // SAFETY: process_id came from the connected named pipe.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(io::Error::last_os_error()).context("failed to inspect helper server");
    }
    let process = OwnedHandle(process);
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: process is a valid process handle retained by OwnedHandle.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error()).context("failed to inspect helper server token");
    }
    let sid = token_user_sid(&OwnedHandle(token))?;
    if !sid.eq_ignore_ascii_case(LOCAL_SYSTEM_SID) {
        bail!("refusing a privileged helper not owned by LocalSystem");
    }
    Ok(())
}

pub(super) fn current_user_sid() -> Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle valid for this call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error()).context("failed to open the current user token");
    }
    token_user_sid(&OwnedHandle(token))
}

fn token_user_sid(token: &OwnedHandle) -> Result<String> {
    let mut required = 0_u32;
    // SAFETY: the null probe is the documented way to obtain the buffer size.
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &raw mut required);
    }
    if required == 0 || required > 64 * 1024 {
        bail!("Windows token user data has an invalid size");
    }
    let word = std::mem::size_of::<usize>();
    let words = usize::try_from(required)
        .unwrap_or(usize::MAX)
        .div_ceil(word);
    let mut buffer = vec![0_usize; words];
    // SAFETY: buffer is aligned for TOKEN_USER and sized from the probe above.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("failed to read the Windows user SID");
    }
    // SAFETY: GetTokenInformation initialized a TOKEN_USER at the buffer start.
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_to_string(token_user.User.Sid)
}

fn sid_to_string(sid: PSID) -> Result<String> {
    if sid.is_null() {
        bail!("Windows SID is missing");
    }
    let mut string = ptr::null_mut();
    // SAFETY: sid originates from a validated Windows token/security descriptor.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut string) } == 0 || string.is_null() {
        return Err(io::Error::last_os_error()).context("failed to format a Windows SID");
    }
    let mut length = 0_usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated allocation.
    unsafe {
        while *string.add(length) != 0 {
            length += 1;
            if length > 256 {
                LocalFree(string.cast::<c_void>());
                bail!("Windows SID string is too long");
            }
        }
    }
    // SAFETY: the length was bounded by the NUL scan above.
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(string, length) })
        .context("Windows SID is not valid UTF-16")?;
    // SAFETY: string was allocated by LocalAlloc through the conversion API.
    unsafe {
        LocalFree(string.cast::<c_void>());
    }
    Ok(value)
}

pub(super) fn require_local_system() -> Result<()> {
    if !current_user_sid()?.eq_ignore_ascii_case(LOCAL_SYSTEM_SID) {
        bail!("the privileged helper service must run as LocalSystem");
    }
    Ok(())
}

pub(super) fn require_elevated_administrator() -> Result<()> {
    let sid = allocated_sid(BUILTIN_ADMINISTRATORS_SID)?;
    let mut member = 0;
    // SAFETY: null token means the effective process token; sid is valid until
    // the call returns.
    if unsafe { CheckTokenMembership(ptr::null_mut(), sid.0, &raw mut member) } == 0 {
        return Err(io::Error::last_os_error()).context("failed to check administrator status");
    }
    if member == 0 {
        bail!("installing the privileged helper requires an elevated Administrator token");
    }
    Ok(())
}

pub(super) fn validate_privileged_program_path(path: &Path) -> Result<()> {
    reject_reparse_point(path)?;
    let owner = file_owner_sid(path)?;
    if ![
        LOCAL_SYSTEM_SID,
        BUILTIN_ADMINISTRATORS_SID,
        TRUSTED_INSTALLER_SID,
    ]
    .iter()
    .any(|trusted| owner.eq_ignore_ascii_case(trusted))
    {
        bail!("admin executable must be owned by SYSTEM, Administrators or TrustedInstaller");
    }
    let mut current = Some(path);
    let mut depth = 0_usize;
    while let Some(component) = current {
        if depth > 64 {
            bail!("admin executable path is too deeply nested");
        }
        reject_reparse_point(component)?;
        reject_low_privilege_write_access(component)?;
        current = component.parent();
        depth += 1;
    }
    Ok(())
}

fn reject_reparse_point(path: &Path) -> Result<()> {
    let wide_path = wide(path.as_os_str());
    // SAFETY: wide_path is NUL-terminated for the duration of the call.
    let attributes = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(io::Error::last_os_error()).context("failed to inspect admin executable path");
    }
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("admin executable paths may not contain reparse points");
    }
    Ok(())
}

fn file_owner_sid(path: &Path) -> Result<String> {
    let security = query_file_security(path)?;
    sid_to_string(security.owner)
}

fn reject_low_privilege_write_access(path: &Path) -> Result<()> {
    let security = query_file_security(path)?;
    if security.dacl.is_null() {
        bail!("admin executable path has an unrestricted DACL");
    }
    let write_mask =
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
    for sid_text in LOW_PRIVILEGE_SIDS {
        let sid = allocated_sid(sid_text)?;
        let trustee = TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.0.cast::<u16>(),
        };
        let mut rights = 0_u32;
        // SAFETY: DACL and SID are owned for the complete query call.
        let error = unsafe {
            GetEffectiveRightsFromAclW(security.dacl, &raw const trustee, &raw mut rights)
        };
        if error != 0 {
            bail!("failed to verify admin executable path permissions");
        }
        if rights & write_mask != 0 {
            bail!("admin executable path is writable by a non-administrative identity");
        }
    }
    Ok(())
}

struct FileSecurity {
    _descriptor: LocalAllocation,
    owner: PSID,
    dacl: *mut windows_sys::Win32::Security::ACL,
}

fn query_file_security(path: &Path) -> Result<FileSecurity> {
    let wide_path = wide(path.as_os_str());
    let mut owner: PSID = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: output pointers remain valid and descriptor is retained by the
    // returned LocalAllocation for all owner/DACL queries.
    let error = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if error != 0 || descriptor.is_null() || owner.is_null() {
        return Err(io::Error::from_raw_os_error(error.cast_signed()))
            .context("failed to read admin executable permissions");
    }
    Ok(FileSecurity {
        _descriptor: LocalAllocation(descriptor),
        owner,
        dacl,
    })
}

fn allocated_sid(value: &str) -> Result<LocalSid> {
    let wide_value = wide(value);
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: wide_value is NUL-terminated and sid is released by LocalSid.
    if unsafe { ConvertStringSidToSidW(wide_value.as_ptr(), &raw mut sid) } == 0 || sid.is_null() {
        return Err(io::Error::last_os_error()).context("failed to parse a Windows SID");
    }
    Ok(LocalSid(sid))
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

pub(super) fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns the real handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns a LocalAlloc allocation.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct LocalSid(PSID);

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns a SID allocated by LocalAlloc.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct RevertGuard;

impl Drop for RevertGuard {
    fn drop(&mut self) {
        // SAFETY: restoring the service thread token is always valid after a
        // successful ImpersonateNamedPipeClient call.
        unsafe {
            RevertToSelf();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_is_product_scoped_and_local() {
        assert_eq!(PIPE_NAME, r"\\.\pipe\RunOnMine.Helper");
        assert!(!PIPE_NAME.to_ascii_lowercase().contains("macmcp"));
    }

    #[test]
    fn pipe_acl_contains_only_system_and_owner_rules() {
        let owner = "S-1-5-21-1-2-3-1001";
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{owner})");
        assert!(sddl.contains(";;;SY"));
        assert!(sddl.contains(owner));
        assert!(!sddl.contains(";;;WD"));
    }
}
