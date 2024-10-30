use std::fs::DirEntry;

pub mod numbers_to_words;
pub mod rsa;

pub fn is_not_hidden(entry: &DirEntry) -> bool {
    match hf::is_hidden(entry.path()) {
        Ok(res) => !res,
        Err(_) => false,
    }
}
