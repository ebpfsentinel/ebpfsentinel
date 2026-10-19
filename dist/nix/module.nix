# NixOS module for the agent and its warden.
#
# The two units are the ones the tarball and the packages install, written
# the way NixOS writes a unit. What they do is identical, and deliberately so:
# the agent self-unshares a user namespace and loads its eBPF through a BPF
# token, the warden holds the capabilities the kernel will not delegate, and
# both run as root because that is what those two mechanisms need. A NixOS
# host that behaved differently here would be a fourth deployment to reason
# about when something does not load.
#
# The package is not defaulted. `package.nix` needs a release version and its
# hashes, which this module cannot invent; point `services.ebpfsentinel.package`
# at a `callPackage` of it.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.ebpfsentinel;
  format = pkgs.formats.yaml { };
  profileFile = name: "${cfg.package}/share/ebpfsentinel/profiles/${name}.yaml";
  generatedConfig = format.generate "ebpfsentinel.yaml" cfg.settings;
  configFile =
    if cfg.configFile != null then
      cfg.configFile
    else if cfg.settings != { } then
      generatedConfig
    else if cfg.profile != null then
      profileFile cfg.profile
    else
      "${cfg.package}/share/ebpfsentinel/ebpfsentinel.yaml";
in
{
  options.services.ebpfsentinel = {
    enable = lib.mkEnableOption "the eBPFsentinel network security agent";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The agent package, built from a published release by `package.nix`,
        which takes the release version and its hashes. There is no default:
        a module cannot choose which release a host runs.
      '';
      example = lib.literalExpression ''
        pkgs.callPackage ./package.nix {
          version = "2026.6.1";
          hashes.x86_64-linux = "sha256-...";
        }
      '';
    };

    settings = lib.mkOption {
      type = format.type;
      default = { };
      description = ''
        The agent configuration, as an attribute set rendered to YAML. Every
        key the agent's reference configuration documents is accepted; the
        module adds none of its own and renames none of them, so the
        documentation of a key is the agent's documentation of it.

        Left empty, the reference configuration shipped in the package is
        used unchanged.
      '';
      example = lib.literalExpression ''
        {
          agent.interfaces = [ "eth0" ];
          firewall = {
            enabled = true;
            mode = "alert";
          };
        }
      '';
    };

    profile = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "home-router"
          "k3s-node"
          "proxmox-host"
        ]
      );
      default = null;
      description = ''
        Start from one of the host profiles shipped in the package instead of
        the reference configuration. A profile is a complete document, so it
        cannot be combined with `settings`: copy the profile out of the
        package and write it as `settings` once you want to change it.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        A configuration file to use as it is, for a configuration kept
        outside the Nix store or managed by something else. Set this or
        `settings` or `profile`, not two of them.
      '';
    };

    openApiPort = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Open the control API port on the host firewall. Off by default: the
        API answers on loopback in the reference configuration, and an
        authenticated control surface reachable from the network is a
        decision rather than a side effect of installing an agent.
      '';
    };

    apiPort = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = ''
        The port `openApiPort` opens. It does not configure the agent: the
        agent reads its own bind address from the configuration, and this
        must match it.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.count (x: x) [
          (cfg.settings != { })
          (cfg.profile != null)
          (cfg.configFile != null)
        ] <= 1;
        message = "services.ebpfsentinel: set at most one of settings, profile and configFile; they are three ways to name the same file.";
      }
      {
        assertion = lib.versionAtLeast config.boot.kernelPackages.kernel.version "6.9";
        message = "services.ebpfsentinel: the agent loads eBPF through a BPF token, which needs kernel 6.9 or newer; this host runs ${config.boot.kernelPackages.kernel.version}.";
      }
    ];

    environment.systemPackages = [ cfg.package ];

    # The agent's redb stores resolve relative to its working directory, and
    # the API key it draws for itself at first start lives in a directory it
    # narrows to 0700. Both are created here so the mode is right on a host
    # whose umask is loose.
    systemd.tmpfiles.rules = [
      "d /var/lib/ebpfsentinel 0755 root root -"
      "d /var/lib/ebpfsentinel/data 0755 root root -"
      "d /var/lib/ebpfsentinel/captures 0755 root root -"
      "d /var/lib/ebpfsentinel/auth 0700 root root -"
    ];

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openApiPort [ cfg.apiPort ];

    systemd.services.ebpfsentinel-warden = {
      description = "eBPFsentinel warden (privileged kernel-operation broker)";
      documentation = [ "https://github.com/ebpfsentinel/ebpfsentinel" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      startLimitBurst = 5;
      startLimitIntervalSec = 300;

      serviceConfig = {
        Type = "simple";
        # The control socket directory, removed when the broker stops.
        RuntimeDirectory = "ebpfsentinel";
        RuntimeDirectoryMode = "0755";
        # --uid 0: the agent maps namespace-0 to real root and presents uid 0
        # over SO_PEERCRED, and only that uid is served.
        ExecStart = "${cfg.package}/bin/ebpfsentinel-warden serve /run/ebpfsentinel/warden.sock --uid 0";
        Restart = "on-failure";
        RestartSec = "2s";
        # The agent is stopped first and may be mid-call here; killing the
        # broker under a call in flight turns an ordered stop into a socket
        # error in the agent's last log line.
        TimeoutStopSec = "20s";
      };
    };

    systemd.services.ebpfsentinel = {
      description = "eBPFsentinel Network Security Agent";
      documentation = [ "https://github.com/ebpfsentinel/ebpfsentinel" ];
      after = [
        "network-online.target"
        "ebpfsentinel-warden.service"
      ];
      # Wants rather than Requires: a warden restart must not tear the agent
      # down, since the agent holds its own eBPF and maps and its warden
      # client reconnects.
      wants = [
        "network-online.target"
        "ebpfsentinel-warden.service"
      ];
      wantedBy = [ "multi-user.target" ];

      startLimitBurst = 5;
      startLimitIntervalSec = 300;

      environment = {
        EBPFSENTINEL_WARDEN_SOCK = "/run/ebpfsentinel/warden.sock";
        # The objects live in the store, so the agent is told where rather
        # than looking in the two installed directories, neither of which
        # exists on a NixOS host.
        EBPF_PROGRAM_DIR = "${cfg.package}/lib/ebpfsentinel";
      };

      serviceConfig = {
        Type = "simple";
        # The agent's bootstrap connects to the warden once and does not
        # retry, so the socket has to be there first.
        ExecStartPre = "${pkgs.runtimeShell} -c 'for _ in $(seq 1 100); do [ -S /run/ebpfsentinel/warden.sock ] && exit 0; sleep 0.1; done; echo \"warden socket not ready\" >&2; exit 1'";
        WorkingDirectory = "/var/lib/ebpfsentinel";
        StateDirectory = "ebpfsentinel";
        ExecStart = "${cfg.package}/bin/ebpfsentinel-agent --config ${configFile}";
        # The agent handles SIGHUP exactly like a file change or a reload
        # through the API.
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "on-failure";
        RestartSec = "5s";
        # Restart=on-failure covers an agent that exits, not one still
        # running and no longer working: the agent withholds its ping once a
        # minute has gone by with no pass over its ring buffers, so a stall
        # costs one restart instead of a silent datapath.
        WatchdogSec = "90s";
        NotifyAccess = "main";
        # The servers drain in 5s, a running capture closes its file in 2s,
        # and a stop waiting on the warden can hold a brokered call for 10s.
        TimeoutStopSec = "20s";
        LimitMEMLOCK = "infinity";
        # Deliberately no NoNewPrivileges: it would block the user-namespace
        # setup the BPF token depends on.
      };
    };
  };
}
