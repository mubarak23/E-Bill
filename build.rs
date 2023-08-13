use std::{
    env, fs,
    path::{Path, PathBuf},
};

const IDENTITY_FOLDER_PATH: &str = "identity";
const BILLS_FOLDER_PATH: &str = "bills";
const CONTACT_MAP_FOLDER_PATH: &str = "contacts";
const CSS_FOLDER_PATH: &str = "css";
const IMAGE_FOLDER_PATH: &str = "image";
const TEMPLATES_FOLDER_PATH: &str = "templates";
pub const BOOTSTRAP_FOLDER_PATH: &str = "bootstrap";
const BILLS_KEYS_FOLDER_PATH: &str = "bills_keys";
const COPY_DIR: [&str; 8] = [
    IDENTITY_FOLDER_PATH,
    BILLS_FOLDER_PATH,
    CONTACT_MAP_FOLDER_PATH,
    CSS_FOLDER_PATH,
    IMAGE_FOLDER_PATH,
    TEMPLATES_FOLDER_PATH,
    BOOTSTRAP_FOLDER_PATH,
    BILLS_KEYS_FOLDER_PATH,
];

/// A helper function for recursively copying a directory.
fn copy_dir<P, Q>(from: P, to: Q)
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let to = to.as_ref().to_path_buf();
    for path in fs::read_dir(from).unwrap() {
        let path = path.unwrap().path();
        let to = to.clone().join(path.file_name().unwrap());
        if path.is_file() {
            fs::copy(&path, to).unwrap();
        } else if path.is_dir() {
            if !to.exists() {
                fs::create_dir(&to).unwrap();
            }
            copy_dir(&path, to);
        } else {
            /* Skip other content */
        }
    }
}

fn main() {
    init_folders();
    let out = env::var("PROFILE").unwrap();
    for dir in COPY_DIR {
        let out = PathBuf::from(format!("target/{}/{}", out, dir));
        if out.exists() {
            fs::remove_dir_all(&out).unwrap();
        }
        fs::create_dir(&out).unwrap();
        copy_dir(dir, &out);
    }
}

//TODO: for cycle.
fn init_folders() {
    if !Path::new(CONTACT_MAP_FOLDER_PATH).exists() {
        fs::create_dir(CONTACT_MAP_FOLDER_PATH).expect("Can't create folder contacts.");
    }
    if !Path::new(IDENTITY_FOLDER_PATH).exists() {
        fs::create_dir(IDENTITY_FOLDER_PATH).expect("Can't create folder identity.");
    }
    if !Path::new(BILLS_FOLDER_PATH).exists() {
        fs::create_dir(BILLS_FOLDER_PATH).expect("Can't create folder bills.");
    }
    if !Path::new(CSS_FOLDER_PATH).exists() {
        fs::create_dir(CSS_FOLDER_PATH).expect("Can't create folder css.");
    }
    if !Path::new(IMAGE_FOLDER_PATH).exists() {
        fs::create_dir(IMAGE_FOLDER_PATH).expect("Can't create folder image.");
    }
    if !Path::new(TEMPLATES_FOLDER_PATH).exists() {
        fs::create_dir(TEMPLATES_FOLDER_PATH).expect("Can't create folder templates.");
    }
    if !Path::new(BOOTSTRAP_FOLDER_PATH).exists() {
        fs::create_dir(BOOTSTRAP_FOLDER_PATH).expect("Can't create folder bootstrap.");
    }
    if !Path::new(BILLS_KEYS_FOLDER_PATH).exists() {
        fs::create_dir(BILLS_KEYS_FOLDER_PATH).expect("Can't create folder bills_keys.");
    }
}
