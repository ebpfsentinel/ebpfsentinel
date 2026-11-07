# Evaluation checks for package.nix and module.nix.
#
# Nothing is built and nothing is fetched but nixpkgs itself: every check
# reads what an evaluation produces, which is where these two files can be
# wrong without a NixOS host to boot. Run by `dist/nix/check.sh`, which pins
# the nixpkgs it evaluates against; it prints the checks that held and throws
# naming the first that did not.
#
#   nix-instantiate --eval --strict dist/nix/check.nix --arg nixpkgs <path>
{ nixpkgs }:

let
  pkgs = import nixpkgs {
    system = "x86_64-linux";
    config = { };
    overlays = [ ];
  };
  inherit (pkgs) lib;

  unitFile = name: builtins.readFile (./.. + "/${name}");

  # The value of one `Key=` line in a unit the tarball and the packages
  # install, so the module is held to the same file they are.
  unitValue =
    name: key:
    let
      matches = lib.filter (l: lib.hasPrefix "${key}=" l) (lib.splitString "\n" (unitFile name));
    in
    if matches == [ ] then
      throw "${name} has no ${key}= line"
    else
      lib.removePrefix "${key}=" (lib.head matches);

  package = pkgs.callPackage ./package.nix {
    version = "2026.6.1";
    hashes.x86_64-linux = lib.fakeHash;
  };

  packageLaterRelease = pkgs.callPackage ./package.nix {
    version = "2026.6.1";
    release = "2026.7.0";
    hashes.x86_64-linux = lib.fakeHash;
  };

  evalWith =
    extra:
    import "${nixpkgs}/nixos/lib/eval-config.nix" {
      system = "x86_64-linux";
      modules = [
        ./module.nix
        {
          services.ebpfsentinel = {
            enable = true;
            inherit package;
          };
          boot.kernelPackages = lib.mkDefault pkgs.linuxPackages_6_12;
          system.stateVersion = "26.05";
        }
        extra
      ];
    };

  # Only the module's own: a configuration with no file systems and no boot
  # loader fails NixOS's assertions too, and those are not the module's.
  failedAssertions =
    extra:
    lib.filter (lib.hasPrefix "services.ebpfsentinel:") (
      map (a: a.message) (lib.filter (a: !a.assertion) (evalWith extra).config.assertions)
    );

  base = (evalWith { }).config;
  agent = base.systemd.services.ebpfsentinel;
  warden = base.systemd.services.ebpfsentinel-warden;

  withSettings = (evalWith { services.ebpfsentinel.settings.agent.interfaces = [ "enp1s0" ]; }).config;
  withProfile = (evalWith { services.ebpfsentinel.profile = "k3s-node"; }).config;

  checks = {
    "the tarball is fetched from the release repository" =
      lib.head package.src.urls
      == "https://github.com/ebpfsentinel/ebpfsentinel-release/releases/download/v2026.6.1/ebpfsentinel-2026.6.1-linux-amd64.tar.gz";

    "the tag is the release and the file name is the agent's version" =
      lib.head packageLaterRelease.src.urls
      == "https://github.com/ebpfsentinel/ebpfsentinel-release/releases/download/v2026.7.0/ebpfsentinel-2026.6.1-linux-amd64.tar.gz";

    "a missing hash fails evaluation" =
      let
        r = builtins.tryEval (
          (pkgs.callPackage ./package.nix {
            version = "2026.6.1";
            hashes = { };
          }).src.urls
        );
      in
      !r.success;

    "the package is published for the two architectures" =
      package.meta.platforms == [
        "aarch64-linux"
        "x86_64-linux"
      ];

    "a host on the floor evaluates with no failed assertion" = failedAssertions { } == [ ];

    "a host below the floor fails evaluation naming the kernel" =
      failedAssertions { boot.kernelPackages = pkgs.linuxPackages_6_6; } == [
        "services.ebpfsentinel: the agent needs kernel 6.12 or newer; this host runs ${pkgs.linuxPackages_6_6.kernel.version}."
      ];

    "settings and a profile together fail evaluation" =
      failedAssertions {
        services.ebpfsentinel.settings.agent.interfaces = [ "enp1s0" ];
        services.ebpfsentinel.profile = "k3s-node";
      } == [
        "services.ebpfsentinel: set at most one of settings, profile and configFile; they are three ways to name the same file."
      ];

    "the agent starts the package's binary on the reference configuration" =
      agent.serviceConfig.ExecStart
      == "${package}/bin/ebpfsentinel-agent --config ${package}/share/ebpfsentinel/ebpfsentinel.yaml";

    "settings become the configuration the agent starts on" =
      lib.hasInfix "-ebpfsentinel.yaml" withSettings.systemd.services.ebpfsentinel.serviceConfig.ExecStart
      && !(lib.hasInfix "share/ebpfsentinel" withSettings.systemd.services.ebpfsentinel.serviceConfig.ExecStart);

    "a profile is read from the package" =
      lib.hasSuffix "/share/ebpfsentinel/profiles/k3s-node.yaml" withProfile.systemd.services.ebpfsentinel.serviceConfig.ExecStart;

    "the warden is served on the socket the agent is told about" =
      warden.serviceConfig.ExecStart
      == "${package}/bin/ebpfsentinel-warden serve /run/ebpfsentinel/warden.sock --uid 0"
      && agent.environment.EBPFSENTINEL_WARDEN_SOCK == "/run/ebpfsentinel/warden.sock";

    "the agent loads its objects from the store" =
      agent.environment.EBPF_PROGRAM_DIR == "${package}/lib/ebpfsentinel";

    "both units start at boot and the agent after the warden" =
      lib.elem "multi-user.target" agent.wantedBy
      && lib.elem "multi-user.target" warden.wantedBy
      && lib.elem "ebpfsentinel-warden.service" agent.after
      && lib.elem "ebpfsentinel-warden.service" agent.wants;

    "the agent unit matches the installed one where the documentation says it does" =
      lib.all (key: toString agent.serviceConfig.${key} == unitValue "ebpfsentinel.service" key) [
        "Type"
        "WatchdogSec"
        "NotifyAccess"
        "TimeoutStopSec"
        "LimitMEMLOCK"
        "Restart"
        "RestartSec"
      ];

    "the warden unit matches the installed one" =
      lib.all (key: toString warden.serviceConfig.${key} == unitValue "ebpfsentinel-warden.service" key) [
        "Type"
        "TimeoutStopSec"
        "Restart"
        "RestartSec"
      ];

    "the agent waits for the warden socket the way the installed unit does" =
      lib.hasInfix (lib.removePrefix "/bin/sh -c " (unitValue "ebpfsentinel.service" "ExecStartPre")) agent.serviceConfig.ExecStartPre;

    "the state directory and auth/ at 0700 are created" =
      lib.elem "d /var/lib/ebpfsentinel/auth 0700 root root -" base.systemd.tmpfiles.rules
      && lib.elem "d /var/lib/ebpfsentinel/data 0755 root root -" base.systemd.tmpfiles.rules;

    "the API port stays closed unless asked" =
      !(lib.elem 8080 base.networking.firewall.allowedTCPPorts)
      && lib.elem 8080 (evalWith { services.ebpfsentinel.openApiPort = true; }).config.networking.firewall.allowedTCPPorts;
  };

  failed = lib.attrNames (lib.filterAttrs (_: ok: !ok) checks);
in
if failed == [ ] then
  map (name: "ok: ${name}") (lib.attrNames checks)
else
  throw "failed: ${lib.concatStringsSep "; " failed}"
