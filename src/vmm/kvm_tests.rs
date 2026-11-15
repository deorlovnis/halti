//! The engine on a real VM: Cloud Hypervisor with KVM, the agent image as a disk with the real
//! shim as its first process, and the real door. Linux with /dev/kvm only, and by hand, with the
//! VM program, the box kernel and a folder of box images (`<image>/<64 hex>.img`) installed as
//! install-linux.sh will install them, owned by root:
//!
//!     HALTI_KVM_PROGRAM=/usr/local/lib/halti/cloud-hypervisor \
//!     HALTI_KVM_KERNEL=/usr/local/lib/halti/images/bzImage \
//!     HALTI_KVM_IMAGES=/usr/local/lib/halti/images \
//!     cargo test --bin halti vmm::kvm_tests -- --ignored --nocapture
//!
//! It makes the box's disk as a box's store makes it (mkfs.ext4 in a sparse file).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use std::{env, fs};

use super::*;
use crate::door::{BoxCa, Config, Door};

/// Dials the exec port at the local id (1), the server's (2) and the box's own (3), and asks each
/// to run `touch /tmp/inside-ran` as root. Prints what each did.
const INSIDE_DIAL: &str = "
import socket, struct
def s(b): return struct.pack(\">I\", len(b)) + b
argv = [b\"touch\", b\"/tmp/inside-ran\"]
req = bytes([1, 1, 0, 0, 0, 0, 0]) + struct.pack(\">H\", len(argv)) + b\"\".join(s(a) for a in argv) + struct.pack(\">H\", 0)
for cid in (1, 2, 3):
    c = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    c.settimeout(3)
    try:
        c.connect((cid, 7001))
    except Exception as e:
        print(\"id %d: not connected: %s\" % (cid, e))
        continue
    try:
        c.sendall(b\"R\" + s(req))
        print(\"id %d: connected; answer %r\" % (cid, c.recv(64)))
    except Exception as e:
        print(\"id %d: connected; then %s\" % (cid, e))
";

/// Dials the server's ports 9 and 10 from inside the box. Prints what each did.
const SERVER_DIAL: &str = "
import socket
for port in (9, 10):
    c = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    c.settimeout(3)
    try:
        c.connect((2, port))
        print(\"port %d: connected\" % port)
    except Exception as e:
        print(\"port %d: not connected: %s\" % (port, e))
";

/// Stops the VM when the test ends, however it ends.
struct Running<'a>(&'a CloudHypervisor, String);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let _ = self.0.stop(&self.1);
    }
}

fn sh(engine: &CloudHypervisor, name: &str, root: bool, script: &str) -> String {
    let out = engine.run_in(name, root, &["sh".into(), "-c".into(), script.into()], &[], b"", RUN_LIMIT).unwrap_or_else(|e| panic!("{script}: {e:#}"));
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
#[ignore = "needs Linux with /dev/kvm, Cloud Hypervisor, its kernel and an agent image disk: see the top of this file"]
fn a_box_boots_runs_as_the_agent_and_as_root_and_keeps_its_disk_across_a_stop() {
    let var = |name: &str| env::var_os(name).map(PathBuf::from);
    let (Some(program), Some(kernel), Some(images)) = (var("HALTI_KVM_PROGRAM"), var("HALTI_KVM_KERNEL"), var("HALTI_KVM_IMAGES")) else {
        panic!("HALTI_KVM_PROGRAM, HALTI_KVM_KERNEL and HALTI_KVM_IMAGES must be set: see the top of this file");
    };
    let dir = PathBuf::from(format!("/tmp/hk-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("open")).unwrap();
    let engine = CloudHypervisor { program, kernel, images, kvm: "/dev/kvm".into(), sockets: dir.join("ws"), waits: Waits::REAL };
    engine.available().unwrap();
    let image = engine.image_digest(names::AGENT_IMAGE).unwrap();
    println!("image: {image}");
    let name = format!("{}0123456789ab-kvm", names::WS_BOX_VM_PREFIX);
    let paths = engine.paths(&name).unwrap();
    let layout = store::Layout::under(&dir).unwrap();
    let disk = layout.bundle("kvm");
    store::create(&layout, &disk, "").unwrap();
    let console = dir.join("open/kvm.console");
    let spec = VmSpec {
        name: name.clone(),
        image,
        cpus: 2,
        memory: "1G".into(),
        socket: paths.vsock.clone(),
        mounts: vec![],
        docker: false,
        rosetta: false,
        disk: Some(disk.clone()),
        console: Some(console.clone()),
    };

    // The door first, as a run starts it: it dials until the box answers on its port.
    let ca = Arc::new(BoxCa::generate("kvm").unwrap());
    let log = dir.join("log/door.log");
    let door = Door::start(Config {
        name: "kvm".into(),
        socket: paths.vsock.clone(),
        port: Some(names::DOOR_PORT),
        allow: vec![],
        model: None,
        sites: vec![],
        net: Default::default(),
        log: log.clone(),
        ca: Some(ca.clone()),
        log_key: [5; 32],
        browser: None,
        browser_socket: None,
        browser_tokens: Default::default(),
    })
    .unwrap();

    let started = Instant::now();
    engine.run(&spec).unwrap_or_else(|e| panic!("{e:#}\nconsole: {}\nthe VM program: {}", console_tail(&console), console_tail(&program_log(&console))));
    let running = Running(&engine, name.clone());
    println!("the shim answered on the exec port {} ms after the start", started.elapsed().as_millis());
    assert!(engine.running(&name));

    // As the agent and as root: who, with which PATH, in which folder.
    let who = "id -u; id -g; echo \"$PATH\"; pwd; echo \"$HOME\"";
    let agent = sh(&engine, &name, false, who);
    let root = sh(&engine, &name, true, who);
    println!("as the agent: {}", agent.trim().replace('\n', " | "));
    println!("as root: {}", root.trim().replace('\n', " | "));
    let path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    assert_eq!(agent, format!("1000\n1000\n{path}\n/home/agent\n/home/agent\n"));
    assert_eq!(root, format!("0\n0\n{path}\n/home/agent\n/root\n"));
    // an agent's command through exec gives its exit code, with its variables
    let status = engine.exec(&name, &[("A".into(), "b".into())], &["sh".into(), "-c".into(), "[ \"$A\" = b ] && exit 3".into()], false).unwrap();
    assert_eq!(status.code(), Some(3));
    // bytes in and bytes out, also more than the sockets hold, which cat echoes as it reads
    assert_eq!(engine.pipe(&name, &["cat".into()], b"through the box").unwrap(), b"through the box");
    let large: Vec<u8> = (0..4 << 20).map(|i: u32| (i % 251) as u8).collect();
    assert!(engine.pipe(&name, &["cat".into()], &large).unwrap() == large, "4 MiB through cat");

    // What the shim set up: the box's folders from its disk, the agent's, and no network but lo.
    let mounts = sh(&engine, &name, false, "for d in /home/agent /work /downloads; do stat -c '%n %u' $d; done; ls /sys/class/net");
    println!("folders and network devices: {}", mounts.trim().replace('\n', " | "));
    assert_eq!(mounts, "/home/agent 1000\n/work 1000\n/downloads 1000\nlo\n");
    // The programs the image unpacked from others' archives are root's, as the image's own are.
    let owners = sh(&engine, &name, false, "stat -c '%n %u:%g' /usr/local/bin/dockerd /usr/local/bin/gh /usr/local/bin/uv /usr/local/bin/halti-shim");
    println!("owners in the image: {}", owners.trim().replace('\n', " | "));
    assert_eq!(owners, "/usr/local/bin/dockerd 0:0\n/usr/local/bin/gh 0:0\n/usr/local/bin/uv 0:0\n/usr/local/bin/halti-shim 0:0\n");

    // The CA, as a run installs it, and a request through the door over vsock: a host the box
    // may not reach is refused by the door, which logs it.
    engine.install_ca(&name, &ca.cert_pem()).unwrap();
    assert_eq!(sh(&engine, &name, false, &format!("test -s {} && echo there", engine::CA_CERT)), "there\n");
    let refused = "curl -s -o /dev/null -w '%{http_connect}' -x http://127.0.0.1:3128 https://nowhere.example.com/ || true";
    let answer = sh(&engine, &name, false, refused);
    println!("through the door, a refused host: CONNECT answered {answer}");
    assert_eq!(answer, "403");
    let logged = fs::read_to_string(&log).unwrap();
    assert!(logged.contains("nowhere.example.com"), "{logged}");

    // A program in the box that dials the exec service itself, at every id it could reach it by,
    // asking to run a command as root. On this kernel none of these dials connects, so the shim's
    // own check of its peer is not reached here (box/shim tests it with a made-up peer).
    let dials = sh(&engine, &name, false, &format!("python3 -c '{INSIDE_DIAL}'; test -e /tmp/inside-ran && echo ran || echo nothing ran"));
    println!("dials from inside the box to the exec port: {}", dials.trim().replace('\n', " | "));
    assert!(!dials.contains(": connected"), "{dials}");
    assert!(dials.ends_with("nothing ran\n"), "{dials}");

    // A write to the box's disk, with no sync of its own: the stop must keep it.
    sh(&engine, &name, false, "echo kept > /home/agent/kept.txt && echo kept > /work/kept.txt");
    let stopping = Instant::now();
    engine.stop(&name).unwrap();
    let took = stopping.elapsed();
    println!("stopped in {} ms", took.as_millis());
    assert!(!engine.running(&name));
    let printed = String::from_utf8_lossy(&fs::read(&console).unwrap_or_default()).into_owned();
    assert!(took < engine.waits.stop, "the box powered off when asked from inside, with no need for the VM program's stop or a kill: {}", console_tail(&console));
    assert!(printed.contains("reboot: Power down"), "the shim powered the VM off: {}", console_tail(&console));
    assert_eq!(fs::read_dir(&paths.dir).unwrap().count(), 0, "no socket is left");

    // A program's listener beside the VM's socket, for the box to dial the server's port 9.
    let left = std::os::unix::net::UnixListener::bind(paths.dir.join("vsock.sock_9")).unwrap();

    // Boot again on the same disk: the write is there.
    engine.run(&spec).unwrap_or_else(|e| panic!("{e:#}\nconsole: {}", console_tail(&console)));
    let kept = sh(&engine, &name, false, "cat /home/agent/kept.txt /work/kept.txt");
    println!("after the stop and a new start, the box disk holds: {}", kept.trim().replace('\n', " | "));
    assert_eq!(kept, "kept\nkept\n");
    println!("the box's disk takes {} MB of the server's", store::usage(&disk).0 >> 20);
    // and the door, which went on dialing, reaches the new VM
    assert_eq!(sh(&engine, &name, false, refused), "403");

    // The start removed the listener's file, so the box's dial to port 9 finds nothing; a file
    // made after the start, for port 10, shows that such a dial would connect.
    assert!(!paths.dir.join("vsock.sock_9").exists(), "the start removed the listener's file");
    let made = std::os::unix::net::UnixListener::bind(paths.dir.join("vsock.sock_10")).unwrap();
    let dials = sh(&engine, &name, false, &format!("python3 -c '{SERVER_DIAL}'"));
    println!("dials from inside the box to the server: {}", dials.trim().replace('\n', " | "));
    let lines: Vec<&str> = dials.lines().collect();
    assert!(lines[0].starts_with("port 9: not connected"), "{dials}");
    assert_eq!(lines[1], "port 10: connected", "{dials}");
    drop((left, made));
    fs::remove_file(paths.dir.join("vsock.sock_10")).unwrap();

    // As if another halti had started the VM and been killed: it is found by its command line,
    // and stopped from inside.
    let child = CHILDREN.lock().unwrap().remove(&name).expect("this halti's child");
    let pid = child.id() as i32;
    assert!(engine.running(&name), "found without this halti's child");
    assert_eq!(engine.pid(&name, &paths), Some(pid));
    let stopping = Instant::now();
    engine.stop(&name).unwrap();
    let took = stopping.elapsed();
    println!("another halti's VM stopped in {} ms", took.as_millis());
    assert!(took < engine.waits.stop, "it powered off when asked from inside: {}", console_tail(&console));
    let mut child = child;
    println!("the VM program ended: {}", child.wait().unwrap());
    assert!(!engine.running(&name));

    drop(running);
    assert!(!engine.running(&name));
    drop(door);
    let _ = fs::remove_dir_all(&dir);
}
