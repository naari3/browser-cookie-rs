use std::sync::Arc;

use browser_cookie::Chrome;
use reqwest::blocking::Client;
use reqwest_cookie_store::CookieStoreMutex;

fn main() {
    let mut chrome = Chrome::new(None, "nicovideo.jp".to_string(), None);
    // let cookies = chrome.get_cookies("https://www.rust-lang.org/").unwrap();
    let cookie_store = chrome.load().unwrap();
    // println!("{:x?}", cookie_store);

    let jar = Arc::new(CookieStoreMutex::new(cookie_store));
    let client = Client::builder()
        .cookie_provider(jar.clone())
        .build()
        .unwrap();

    let res = client
        .get("https://account.nicovideo.jp/my/account")
        .send()
        .unwrap();

    if res.url().to_string() != "https://account.nicovideo.jp/my/account" {
        panic!("Can't login! Current url is {}", res.url().to_string());
    }
}
