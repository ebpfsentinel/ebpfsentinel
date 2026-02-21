fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = "../../proto/ebpfsentinel/v1/alerts.proto";
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .file_descriptor_set_path(out_dir.join("ebpfsentinel.v1.bin"))
        .compile_protos(&[proto_path], &["../../proto"])?;

    println!("cargo:rerun-if-changed={proto_path}");
    Ok(())
}
