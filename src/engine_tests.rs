//! What every box engine must give a box, asked through `Vms` alone, so another engine can't quietly
//! give less: no network device, no way out but the door, commands that run as the agent, and
//! nothing kept in the engine's own files, so what the box writes outside its folders is gone once
//! it stops.
//!
//! It runs a real VM, so only on request, on the engine HALTI_E2E_ENGINE names as `[box] engine`
//! does, with its agent image installed (HALTI_E2E_AGENT_IMAGE names another one):
//!
//!     HALTI_E2E_ENGINE=container cargo test --bin halti engine_tests -- --ignored --nocapture
//!     HALTI_E2E_ENGINE=cloud-hypervisor cargo test --bin halti engine_tests -- --ignored --nocapture
//!
//! `mise run e2e-box` runs it on `container`. Cloud Hypervisor is the one install-linux.sh
//! installs, with the VMs' sockets in the test's folder.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, fs, process};

use crate::boxes::store;
use crate::config::{Engine, Word};
use crate::door::{BoxCa, Config, Door};
use crate::engine::{self, Mount, VmSpec, Vms};
use crate::{names, vmm};

/// The engine under test, and what it asks of a box's VM: its name, and the socket the door dials,
/// with the port the door asks for there (`door::Config`).
struct Under {
    vms: Box<dyn Vms>,
    name: String,
    socket: PathBuf,
    port: Option<u32>,
}

/// The engine `wanted` names, with what it makes kept in `dir`.
fn engine_named(wanted: &str, dir: &Path) -> Under {
    let known = Engine::ALL.iter().map(|e| e.name()).collect::<Vec<_>>().join(", ");
    let engine = Engine::ALL.iter().copied().find(|e| e.name() == wanted).unwrap_or_else(|| panic!("HALTI_E2E_ENGINE is {wanted}, not one of {known}"));
    let id = process::id();
    match engine {
        Engine::Container => Under { vms: Box::new(engine::Container), name: format!("halti-e2e-engine-{id}"), socket: dir.join("door.sock"), port: None },
        Engine::CloudHypervisor => {
            // It runs only a workspace's boxes, each dialed on its own vsock device.
            let named = format!("e2e-{id}");
            let sockets = dir.join("ws");
            let socket = sockets.join(format!("{named}{}", names::VM_SOCKETS)).join(store::VM_VSOCK);
            let vms = vmm::CloudHypervisor { sockets, ..vmm::CloudHypervisor::installed() };
            Under { vms: Box::new(vms), name: format!("{}{named}", names::WS_BOX_VM_PREFIX), socket, port: Some(names::DOOR_PORT) }
        }
    }
}

/// The box's VM: its home a folder of `dir`, or for an engine given the box's disk, a new disk.
fn spec(under: &Under, image: &str, dir: &Path) -> VmSpec {
    let (mounts, disk, console) = if under.vms.takes_disk() {
        let layout = store::Layout::under(dir).unwrap();
        let disk = layout.bundle("e2e");
        store::create(&layout, &disk, "").unwrap();
        (Vec::new(), Some(disk), Some(layout.console("e2e")))
    } else {
        let home = dir.join("home");
        fs::create_dir(&home).unwrap();
        (vec![Mount { host: home, guest: "/home/agent".into(), readonly: false }], None, None)
    };
    VmSpec { name: under.name.clone(), image: image.into(), cpus: 2, memory: "2G".into(), socket: under.socket.clone(), mounts, docker: false, rosetta: false, disk, console }
}

/// The VM is stopped when the test ends, however it ends.
struct Stopped<'a>(&'a dyn Vms, &'a str);

impl Drop for Stopped<'_> {
    fn drop(&mut self) {
        let _ = self.0.stop(self.1);
    }
}

/// What `script` prints, run in the VM through `pipe`.
fn out(vms: &dyn Vms, name: &str, script: &str) -> String {
    let cmd = ["sh".to_string(), "-c".to_string(), script.to_string()];
    let printed = vms.pipe(name, &cmd, b"").unwrap_or_else(|e| panic!("{script}: {e:#}"));
    String::from_utf8_lossy(&printed).into_owned()
}

#[test]
#[ignore = "runs a real VM on the engine HALTI_E2E_ENGINE names; see the top of this file"]
fn an_engine_gives_a_box_only_the_door_runs_it_as_the_agent_and_keeps_nothing_of_it() {
    let Some(wanted) = env::var_os("HALTI_E2E_ENGINE") else {
        eprintln!("HALTI_E2E_ENGINE isn't set: skipping");
        return;
    };
    // A short path, for the sockets in it.
    let dir = PathBuf::from(format!("/tmp/he-{}", process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let under = engine_named(&wanted.to_string_lossy(), &dir);
    let (vms, name) = (&*under.vms, under.name.as_str());
    vms.available().unwrap_or_else(|e| panic!("{e:#}"));
    let image = vms.image_digest(&env::var("HALTI_E2E_AGENT_IMAGE").unwrap_or(names::AGENT_IMAGE.into())).unwrap();
    let spec = spec(&under, &image, &dir);

    let ca = Arc::new(BoxCa::generate("e2e").unwrap());
    let log = dir.join("log/door.log");
    let door = Door::start(Config {
        name: "e2e".into(),
        socket: under.socket.clone(),
        port: under.port,
        allow: vec![],
        model: None,
        sites: vec![],
        net: Default::default(),
        log: log.clone(),
        ca: Some(ca.clone()),
        log_key: [7; 32],
        browser: None,
        browser_socket: None,
        browser_tokens: Default::default(),
        requests: None,
    })
    .unwrap();
    let running = Stopped(vms, name);
    vms.run(&spec).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(vms.running(name));
    vms.install_ca(name, &ca.cert_pem()).unwrap();

    // Commands run as the agent, with the environment they are given, and say how they ended.
    let check = "test \"$(id -u):$(id -g):$HOME:$A\" = 1000:1000:/home/agent:b && exit 3".to_string();
    let env = [engine::agent_env(true), vec![("A".into(), "b".into())]].concat();
    let status = vms.exec(name, &env, &["sh".into(), "-c".into(), check], false).unwrap();
    assert_eq!(status.code(), Some(3), "as the agent, with its environment");
    assert_eq!(out(vms, name, "id -u; id -g"), "1000\n1000\n", "what is piped runs as the agent too");
    assert_eq!(out(vms, name, "find / -xdev -perm /6000 -type f 2>/dev/null; true"), "", "no setuid program makes the agent anyone else");

    // No network device but loopback. Through the proxy the door answers, and refuses a host no
    // rule allows; around it nothing answers, and the door sees nothing.
    assert_eq!(out(vms, name, "ls /sys/class/net"), "lo\n");
    let refused = "curl -s -o /dev/null -w '%{http_connect}' -m 20 -x http://127.0.0.1:3128 https://nowhere.example.com/; true";
    assert_eq!(out(vms, name, refused), "403", "the door's answer");
    let logged = fs::read_to_string(&log).unwrap();
    assert!(logged.contains("nowhere.example.com"), "{logged}");
    for around in ["https://example.com", "http://1.1.1.1", "http://192.168.64.1", "http://10.0.2.2"] {
        let tried = out(vms, name, &format!("curl -sS -m 5 --noproxy '*' {around} >/dev/null 2>&1 && echo reached || echo unreached"));
        assert_eq!(tried, "unreached\n", "{around}");
    }
    assert_eq!(fs::read_to_string(&log).unwrap(), logged, "only the refused host reached the door");

    // What the box writes outside its folders is in memory, and the agent can write nowhere else.
    for path in ["/tmp", "/var/tmp"] {
        assert_eq!(out(vms, name, &format!("grep -q ' {path} tmpfs ' /proc/mounts && echo memory; true")), "memory\n", "{path}");
    }
    let writable = format!(
        "find / -xdev \\( -path /proc -o -path /sys -o -path /dev -o -path /tmp -o -path /var/tmp -o -path /home/agent -o -path /work -o -path /downloads \\) -prune \
         -o -writable ! -type l ! -path {} -print 2>/dev/null; true",
        names::LOCAL_SOCKET
    );
    assert_eq!(out(vms, name, &writable), "", "the agent can write on the system");

    // Stopped, the VM is gone, and its socket. Started again, it has its home, and nothing else it
    // wrote: not the agent's files outside its home, nor the CA root put in the system.
    out(vms, name, "echo gone > /tmp/left && echo gone > /var/tmp/left && echo kept > /home/agent/kept");
    vms.stop(name).unwrap();
    assert!(!vms.running(name));
    assert!(!under.socket.exists(), "the door's socket is gone");
    vms.stop(name).unwrap();
    vms.run(&spec).unwrap_or_else(|e| panic!("{e:#}"));
    let left = format!("cat /home/agent/kept; for f in /tmp/left /var/tmp/left {}; do test -e $f && echo $f; done; true", engine::CA_CERT);
    assert_eq!(out(vms, name, &left), "kept\n");

    drop(running);
    assert!(!vms.running(name));
    drop(door);
    let _ = fs::remove_dir_all(&dir);
}
