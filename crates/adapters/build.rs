fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = "../../proto/ebpfsentinel/v1/alerts.proto";
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .file_descriptor_set_path(out_dir.join("ebpfsentinel.v1.bin"))
        .compile_protos(&[proto_path], &["../../proto"])?;

    println!("cargo:rerun-if-changed={proto_path}");

    // The telemetry destination is read with `option_env!`, which is baked into
    // the object file. Without this line cargo has no reason to rebuild when the
    // variable changes, so a cached target directory - which is what every CI
    // build and every Docker layer cache is - would keep yesterday's endpoint,
    // or keep none at all after somebody sets one.
    println!("cargo:rerun-if-env-changed=EBPFSENTINEL_TELEMETRY_ENDPOINT");
    Ok(())
}
