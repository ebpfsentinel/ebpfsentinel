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
          release = "2026.6.1";
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
        assertion = lib.versionAtLeast config.boot.kernelPackages.kernel.version "6.18";
        message = "services.ebpfsentinel: the agent needs kernel 6.18 or newer; this host runs ${config.boot.kernelPackages.kernel.version}.";
      }
      {
        assertion = config.security.allowUserNamespaces;
        message = "services.ebpfsentinel: the agent creates a user namespace as its own unprivileged user, which security.allowUserNamespaces = false refuses.";
      }
    ];

    environment.systemPackages = [ cfg.package ];

    # The agent's redb stores resolve relative to its working directory, and
    # the API key it draws for itself at first start lives in a directory it
    # narrows to 0700. Both are created here so the mode is right on a host
    # whose umask is loose.
    systemd.tmpfiles.rules = [
      "d /var/lib/ebpfsentinel 0750 ebpfsentinel ebpfsentinel -"
      "d /var/lib/ebpfsentinel/data 0750 ebpfsentinel ebpfsentinel -"
      "d /var/lib/ebpfsentinel/captures 0750 ebpfsentinel ebpfsentinel -"
      "d /var/lib/ebpfsentinel/auth 0700 ebpfsentinel ebpfsentinel -"
    ];

    # The agent never runs as root: it runs as this user, with no login and no
    # capability, and maps its user namespace's root onto it. The warden serves
    # only it.
    users.users.ebpfsentinel = {
      isSystemUser = true;
      group = "ebpfsentinel";
      home = "/var/lib/ebpfsentinel";
      description = "eBPFsentinel agent";
    };
    users.groups.ebpfsentinel = { };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openApiPort [ cfg.apiPort ];

    systemd.services.ebpfsentinel-warden = {
      description = "eBPFsentinel warden (privileged kernel-operation broker)";
      documentation = [ "https://github.com/ebpfsentinel/ebpfsentinel" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      # Stopped with the agent and never alone: the agent's own stop command
      # takes the warden down through this binding, and a crash of the agent
      # between two restarts leaves it up.
      bindsTo = [ "ebpfsentinel.service" ];
      unitConfig.RefuseManualStop = true;
      restartIfChanged = false;

      # The guard on program loads is in the store beside the agent's
      # objects, not at the path the images use.
      environment.EBPFSENTINEL_LOAD_GUARD_OBJECT = "${cfg.package}/lib/ebpfsentinel/lsm-bpf-load-guard";

      startLimitBurst = 5;
      startLimitIntervalSec = 300;

      serviceConfig = {
        Type = "simple";
        # The control socket directory, removed when the broker stops.
        RuntimeDirectory = "ebpfsentinel";
        RuntimeDirectoryMode = "0755";
        # --user ebpfsentinel: the agent runs as its own unprivileged user and
        # presents that uid over SO_PEERCRED. Only that uid is served.
        # --policy: what the warden answers, written by the agent binary as
        # root before the agent runs, from the configuration the agent reads,
        # into a directory the agent cannot write.
        ExecStartPre = "${cfg.package}/bin/ebpfsentinel-agent --config ${configFile} warden-policy --output-file /run/ebpfsentinel/warden-policy.json";
        ExecStart = "${cfg.package}/bin/ebpfsentinel-warden serve /run/ebpfsentinel/warden.sock --user ebpfsentinel --policy /run/ebpfsentinel/warden-policy.json";
        Restart = "always";
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
      # `systemctl stop` and `restart` are refused: the way down is
      # `ebpfsentinel-agent stop --reason "..."`, which records who asked and
      # ends the agent with status 79, the one exit not restarted. A switch
      # therefore leaves a changed unit running on its old definition until
      # that stop and the next start; it never fails the switch.
      unitConfig.RefuseManualStop = true;
      restartIfChanged = false;

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
        Restart = "always";
        RestartSec = "5s";
        RestartPreventExitStatus = "79";
        SuccessExitStatus = "79";
        # Restart=always covers an agent that exits, not one still
        # running and no longer working: the agent withholds its ping once a
        # minute has gone by with no pass over its ring buffers, so a stall
        # costs one restart instead of a silent datapath.
        WatchdogSec = "90s";
        NotifyAccess = "main";
        # The servers drain in 5s, a running capture closes its file in 2s,
        # and a stop waiting on the warden can hold a brokered call for 10s.
        TimeoutStopSec = "20s";
        LimitMEMLOCK = "infinity";
        User = "ebpfsentinel";
        Group = "ebpfsentinel";
        # No capability survives into the agent's process on the host. The
        # user namespace it creates starts with a full set of its own, which is
        # all the token needs.
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        # Deliberately no NoNewPrivileges: under it AppArmor refuses the
        # transition into the agent's profile, which is what grants the user
        # namespace on hosts that gate it.
        ProtectSystem = "strict";
        ProtectHome = "yes";
        PrivateTmp = "yes";
        PrivateDevices = "yes";
        ProtectKernelModules = "yes";
        ProtectKernelLogs = "yes";
        ProtectClock = "yes";
        ProtectHostname = "yes";
        RestrictSUIDSGID = "yes";
        RestrictRealtime = "yes";
        LockPersonality = "yes";
        SystemCallArchitectures = "native";
        RestrictNamespaces = "user mnt";
        # The delegated bpffs is mounted on a directory the agent creates here,
        # in its own mount namespace.
        TemporaryFileSystem = "/sys/fs/bpf:mode=1777";
        StateDirectoryMode = "0750";
      };
    };
  };
}
