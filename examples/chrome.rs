use browser_cookie::Chrome;

fn main() {
    let mut chrome = Chrome::new(None, "nicovideo.jp".to_string(), None);
    // let cookies = chrome.get_cookies("https://www.rust-lang.org/").unwrap();
    let cookie_store = chrome.load().unwrap();
    println!("{:x?}", cookie_store);
}
