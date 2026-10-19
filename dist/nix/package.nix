# The agent, the warden and the compiled eBPF objects, taken from a published
# release.
#
# It does not build from source on purpose. The eBPF objects are compiled by a
# pinned nightly against a target nixpkgs does not carry, and a Nix build of
# them would be a second build of the product: the objects a NixOS host loads
# would then be objects nobody signed. Everything executable here comes from
# the release, which is the only place anything is retrieved from.
#
# `version` and `hashes` are required arguments and deliberately have no
# defaults. A default version ages into a lie the first time a release is cut,
# and a hash cannot be guessed: an evaluation without them fails saying so.
#
#   pkgs.callPackage ./package.nix {
#     version = "2026.6.1";
#     hashes = {
#       x86_64-linux = "sha256-...";
#       aarch64-linux = "sha256-...";
#     };
#   }
#
# The hash of a release is the sha256 of its tarball, which is in the signed
# SHA256SUMS of that release; `nix hash convert --hash-algo sha256 <hex>`
# turns it into the SRI form Nix wants. Verify the signature before you take
# the number: see the verification commands in the installation documentation.
{
  lib,
  stdenvNoCC,
  fetchurl,
  version,
  hashes,
}:

let
  systems = {
    x86_64-linux = "amd64";
    aarch64-linux = "arm64";
  };
  system = stdenvNoCC.hostPlatform.system;
  arch =
    systems.${system}
      or (throw "ebpfsentinel is published for ${lib.concatStringsSep " and " (lib.attrNames systems)}, not ${system}");
  hash =
    hashes.${system}
      or (throw "no hash given for ${system}; pass hashes.${system} from the release's SHA256SUMS");
in
stdenvNoCC.mkDerivation {
  pname = "ebpfsentinel";
  inherit version;

  src = fetchurl {
    url = "https://github.com/ebpfsentinel/ebpfsentinel/releases/download/v${version}/ebpfsentinel-${version}-linux-${arch}.tar.gz";
    inherit hash;
  };

  # The binaries are built for a musl target and are statically linked, so
  # there is no interpreter to patch and no library to find. Patching them
  # would change bytes the release signed.
  dontPatchELF = true;
  dontStrip = true;

  installPhase = ''
    runHook preInstall

    install -Dm755 ebpfsentinel-agent "$out/bin/ebpfsentinel-agent"
    install -Dm755 warden "$out/bin/ebpfsentinel-warden"

    mkdir -p "$out/lib/ebpfsentinel"
    cp -a ebpf/. "$out/lib/ebpfsentinel/"

    install -Dm644 ebpfsentinel.yaml "$out/share/ebpfsentinel/ebpfsentinel.yaml"
    mkdir -p "$out/share/ebpfsentinel/profiles"
    install -Dm644 profiles/*.yaml "$out/share/ebpfsentinel/profiles/"
    install -Dm644 LICENSE "$out/share/doc/ebpfsentinel/LICENSE"

    runHook postInstall
  '';

  meta = {
    description = "eBPF network security agent (kernel and userspace)";
    homepage = "https://ebpfsentinel.io";
    license = lib.licenses.agpl3Only;
    platforms = lib.attrNames systems;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    mainProgram = "ebpfsentinel-agent";
  };
}
