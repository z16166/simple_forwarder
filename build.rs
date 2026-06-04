fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let icon_path = std::path::Path::new(&manifest_dir)
            .join("resources")
            .join("icon.ico");
        res.set_icon(icon_path.to_str().unwrap());
        res.compile().unwrap();
    }
}
