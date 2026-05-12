fn main() {
    #[cfg(windows)]
    {
        embed_resource::compile("bunker.rc", embed_resource::NONE);
    }
}
