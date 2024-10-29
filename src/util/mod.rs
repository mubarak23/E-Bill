use std::fs::DirEntry;

pub mod numbers_to_words;
pub mod rsa;

pub unsafe fn structure_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    std::slice::from_raw_parts((p as *const T) as *const u8, size_of::<T>())
}

pub fn is_not_hidden(entry: &DirEntry) -> bool {
    match hf::is_hidden(entry.path()) {
        Ok(res) => !res,
        Err(_) => false,
    }
}
