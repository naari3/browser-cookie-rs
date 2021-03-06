use std::{
    fmt::Display,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    ptr::null_mut,
};

use aes_gcm::{Aes256Gcm, Key, Nonce};
use cookie::Cookie;
use cookie_store::CookieStore;
use rusqlite::{params, Connection};
use serde_json::Value;
use thiserror::Error;
use url::Url;
use valq::query_value;
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{GetLastError, WIN32_ERROR},
        Security::Cryptography::CRYPTPROTECT_UI_FORBIDDEN,
    },
};

#[derive(Debug)]
pub struct Win32Error {
    source: WIN32_ERROR,
}

impl Display for Win32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Win32 error: {:?}", self.source)
    }
}

impl std::error::Error for Win32Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<WIN32_ERROR> for Win32Error {
    fn from(source: WIN32_ERROR) -> Self {
        Self { source }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("io")]
    Io(#[from] std::io::Error),
    #[error("sqlite")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json")]
    Json(#[from] serde_json::Error),
    #[error("aes")]
    Aes(#[from] aes_gcm::Error),
    #[error("win32")]
    Win32(#[from] Win32Error),
    #[error("cookie_store")]
    CookieStore(#[from] cookie_store::Error),
}

fn dpapi_decrypt(encrypted: &mut [u8]) -> Result<Vec<u8>, Error> {
    use windows::Win32::Security::Cryptography::CRYPTOAPI_BLOB;
    // let mut encrypted = Vec::from(encrypted);
    let blobin = CRYPTOAPI_BLOB {
        cbData: encrypted.len() as _,
        pbData: encrypted.as_mut_ptr(),
    };
    let mut blobout = CRYPTOAPI_BLOB::default();
    let _desc = PWSTR::default();
    unsafe {
        let result = windows::Win32::Security::Cryptography::CryptUnprotectData(
            &blobin,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut blobout,
        );
        if !result.as_bool() {
            return Err(Win32Error::from(GetLastError()).into());
        }
        Ok(Vec::from_raw_parts(
            blobout.pbData,
            blobout.cbData as _,
            blobout.cbData as _,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct CookieRecord {
    host_key: String,
    path: String,
    is_secure: bool,
    #[allow(dead_code)]
    expires_utc: Option<usize>,
    name: String,
    value: String,
    encrypted_value: Vec<u8>,
    is_httponly: bool,
}

#[derive(Debug)]
pub struct ChromiumBase {
    #[allow(dead_code)]
    salt: Vec<u8>,
    #[allow(dead_code)]
    iv: Vec<u8>,
    key: Vec<u8>,
    #[allow(dead_code)]
    length: usize,
    cookie_file_path: PathBuf,
    domain_name: String,
}

impl ChromiumBase {
    pub fn new(
        cookie_file_path: PathBuf,
        domain_name: String,
        key_file: File,
    ) -> Result<Self, Error> {
        let reader = BufReader::new(key_file);
        let keys: Value = serde_json::from_reader(reader)?;
        let key64 = query_value!(keys.os_crypt.encrypted_key -> str).unwrap();
        let mut keydpapi = base64::decode(key64).unwrap();

        let key = dpapi_decrypt(&mut keydpapi[5..])?;

        Ok(ChromiumBase {
            salt: vec![],
            iv: vec![],
            key,
            length: 0,
            cookie_file_path,
            domain_name,
        })
    }

    pub fn load(&mut self) -> Result<CookieStore, Error> {
        let conn = Connection::open(self.cookie_file_path.clone())?;
        let sql = "SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly
                FROM cookies WHERE host_key like ?;";
        let mut stmt = conn.prepare(sql)?;
        let cookie_iter = stmt.query_map(
            params![format!("%{}%", self.domain_name)],
            |row| -> Result<CookieRecord, rusqlite::Error> {
                use rusqlite::types::ValueRef::*;
                Ok(CookieRecord {
                    host_key: row.get(0)?,
                    path: row.get(1)?,
                    is_secure: row.get(2)?,
                    expires_utc: match row.get_ref_unwrap(3) {
                        Null => todo!(),
                        Integer(x) => match x {
                            0 => None,
                            x => Some((x as usize / 1000000) - 11644473600),
                        },
                        Real(_) => todo!(),
                        Text(_) => todo!(),
                        Blob(_) => todo!(),
                    },
                    name: row.get(4)?,
                    value: row.get(5)?,
                    encrypted_value: match row.get_ref_unwrap(6) {
                        Text(blob) => blob.to_vec(),
                        Null => todo!(),
                        Integer(_) => todo!(),
                        Real(_) => todo!(),
                        Blob(blob) => blob.to_vec(),
                    },
                    is_httponly: row.get(7)?,
                })
            },
        )?;

        let mut cookie_store = CookieStore::default();
        let cookies = cookie_iter
            .filter_map(|cookie_record| cookie_record.ok())
            .filter_map(|mut cookie_record| {
                if cookie_record.value == "" {
                    cookie_record.value = String::from_utf8(
                        self.decrypt(&mut cookie_record.encrypted_value[..])
                            .unwrap(),
                    )
                    .unwrap();
                }
                let mut domain = cookie_record.host_key.clone();
                if domain.starts_with(".") {
                    domain = domain[1..].to_string();
                }
                let raw_cookie = Cookie::build(cookie_record.name, cookie_record.value)
                    .domain(domain)
                    .path(cookie_record.path)
                    .secure(cookie_record.is_secure)
                    .http_only(cookie_record.is_httponly)
                    .finish();

                let pseudo_url = Url::parse(&format!("http://{}", cookie_record.host_key)).unwrap();

                let cookie = cookie_store::Cookie::try_from_raw_cookie(&raw_cookie, &pseudo_url);

                Some((cookie, pseudo_url))
            });
        for (cookie, reqest_url) in cookies {
            cookie_store.insert(cookie.unwrap(), &reqest_url).unwrap();
        }
        // let cookie_store = CookieStore::from_cookies(cookies, false).unwrap();
        Ok(cookie_store)
    }

    fn decrypt(&mut self, encrypted_value: &mut [u8]) -> Result<Vec<u8>, Error> {
        use aes_gcm::aead::Aead;
        use aes_gcm::NewAead;

        let result = dpapi_decrypt(encrypted_value);
        if let Ok(encrypted_value) = result {
            return Ok(encrypted_value);
        }

        let encrypted_value = &encrypted_value[3..];
        let key = Key::<Aes256Gcm>::clone_from_slice(&self.key);
        let nonce = Nonce::clone_from_slice(&encrypted_value[..12]);
        // let tag = Tag::clone_from_slice(&encrypted_value[encrypted_value.len() - 16..]);

        let cipher = Aes256Gcm::new(&key);
        let cipher_target = [
            &encrypted_value[12..encrypted_value.len() - 16],
            &encrypted_value[encrypted_value.len() - 16..],
        ]
        .concat();
        // let mut buffer = vec![];
        // Ok(cipher.decrypt_in_place_detached(&nonce, cipher_target.as_ref(), &mut buffer, &tag)?)
        Ok(cipher.decrypt(&nonce, cipher_target.as_ref())?)
    }
}

#[derive(Debug)]
pub struct Chrome {
    base: ChromiumBase,
}

impl Chrome {
    pub fn new(
        cookie_file_path: Option<PathBuf>,
        domain_name: String,
        key_file: Option<File>,
    ) -> Chrome {
        let appdata = env!("APPDATA");
        let localappdata = env!("LOCALAPPDATA");

        let cookie_paths = [
            Path::new(&appdata).join("..\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"),
            Path::new(&localappdata).join("Google\\Chrome\\User Data\\Default\\Cookies"),
            Path::new(&appdata).join("Google\\Chrome\\User Data\\Default\\Cookies"),
            Path::new(&appdata)
                .join("..\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"),
            Path::new(&localappdata).join("Google\\Chrome\\User Data\\Default\\Network\\Cookies"),
            Path::new(&appdata).join("Google\\Chrome\\User Data\\Default\\Network\\Cookies"),
        ];

        let cookie_file_path = cookie_file_path
            .or(cookie_paths
                .into_iter()
                .find_map(|path| if path.exists() { Some(path) } else { None }))
            .expect("cookie_file not found");

        let key_paths = [
            Path::new(&appdata).join("..\\Local\\Google\\Chrome\\User Data\\Local State"),
            Path::new(&localappdata).join("Google\\Chrome\\User Data\\Local State"),
            Path::new(&appdata).join("Google\\Chrome\\User Data\\Local State"),
        ];

        let key_file = key_file
            .or(key_paths.iter().find_map(|path| {
                if path.exists() {
                    Some(File::open(path).unwrap())
                } else {
                    None
                }
            }))
            .expect("key_file not found");

        Chrome {
            base: ChromiumBase::new(cookie_file_path, domain_name, key_file).unwrap(),
        }
    }

    pub fn load(&mut self) -> Result<CookieStore, Error> {
        self.base.load()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
