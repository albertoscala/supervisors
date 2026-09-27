# supervisors

Modular eBPF supervisors for adding runtime security to embedded Linux devices without modifying their firmware.

Each supervisor is an independent eBPF program with its own userspace loader and whitelist. It intercepts one class of operation in the kernel and denies anything outside its policy before the operation takes effect.

The design and evaluation are described in the accompanying paper: [Retrofitting Runtime Security onto Legacy Embedded Linux with Modular eBPF Supervisors](Retrofitting_Runtime_Security_onto_Legacy_Embedded_Linux_with_Modular_eBPF_Supervisors.pdf).

## Supervisors

| Supervisor | Scope | Hooks | Policy |
|---|---|---|---|
| [Toll](toll/) | IPv4 traffic | `tcx/ingress`, `tcx/egress` | Allow only whitelisted peers in each direction |
| [Guardian](guardian/) | Executable memory and program execution | `lsm/mmap_file`, `lsm/mmap_addr`, `lsm/file_mprotect`, `lsm/bprm_check_security` | Deny executable memory that is or was writable; allow only whitelisted binaries to execute |

### Toll

Toll attaches to a network interface and inspects every IPv4 packet:

- Ingress: the source address must be listed in `whitelist_arrivals.txt`.
- Egress: the destination address must be listed in `whitelist_departures.txt`.

Other packets are dropped. Non-IPv4 frames are passed through. Each whitelist holds up to 64 addresses.

### Guardian

Guardian enforces policy at the final stage of a memory-corruption exploit, where the attacker must request executable memory or execute a binary through a system call.

| Hook | Denied operations |
|---|---|
| `lsm/mmap_file` | Mappings requesting both `PROT_WRITE` and `PROT_EXEC`; `PROT_EXEC` on `MAP_SHARED` mappings |
| `lsm/mmap_addr` | Mappings below 1 MB |
| `lsm/file_mprotect` | Adding `PROT_EXEC` to a region that is shared, currently writable, or was previously writable |
| `lsm/bprm_check_security` | Executing a binary not in the whitelist, including through `system()` |

Write history is stored in an eBPF hash map keyed by memory descriptor and page address, so it is scoped per process and independent of VMA splits and merges. The execution whitelist is matched by inode: the loader resolves each listed path at startup and passes the inode numbers to the kernel program. The whitelist holds up to 64 binaries.

## Requirements

- Linux kernel with BTF enabled (`/sys/kernel/btf/vmlinux`)
- Toll: TCX support (Linux 6.6 or later)
- Guardian: BPF LSM (Linux 5.7 or later) with `bpf` in the active LSM list (`cat /sys/kernel/security/lsm`); if absent, add it through the `lsm=` kernel parameter
- `clang`, `bpftool`, `libbpf`, `libelf`, `zlib`
- `python3` for the tests
- Root privileges

## Build and run

From the `toll/` or `guardian/` directory:

```sh
make build    # compile the eBPF module and the loader
make run      # start the loader
make test     # build and run the tests
```

The loader reads its whitelists from `loader/rsrc/` and must be run from the supervisor's directory. It remains attached until interrupted with `Ctrl+C`. Decisions are logged to the kernel trace buffer, tagged `[TOLL]` or `[GUARDIAN]`:

```sh
sudo cat /sys/kernel/tracing/trace_pipe
```

## Configuration

### Toll

- Interface: set in `toll/loader/src/loader.c` (default `enp5s0`).
- Whitelists: one IPv4 address per line in `toll/loader/rsrc/whitelist_arrivals.txt` and `whitelist_departures.txt`. Empty lines and lines beginning with `#` are ignored.

Toll enforces its policy as soon as it is attached. With empty whitelists it drops all IPv4 traffic on the interface, including remote sessions.

### Guardian

- Whitelist: one absolute binary path per line in `guardian/loader/rsrc/whitelist_arrivals.txt`. Each path must exist when the loader starts.
- Enforcement: Guardian is built in log-only mode by default. It logs every decision but blocks nothing. To enforce, uncomment `#define ENFORCE` in `guardian/module/src/module.bpf.c` and rebuild.

The intended rollout is to run in log-only mode through normal operation, add every legitimate binary reported in the log to the whitelist, and then enable enforcement. In enforce mode the whitelist must include the shell and any tools needed to administer the device.

## Tests

`toll/test/test_toll.py` runs unit tests against the eBPF programs without attaching them, and an integration test that runs the loader inside an isolated network namespace. The host network configuration is not modified.

```sh
cd toll
sudo python3 test/test_toll.py loader/bin/loader [--only unit|integration]
```

`guardian/test/test_guardian.py` starts the loader with a test whitelist and verifies that whitelisted binaries run without false positives from the memory hooks, that non-whitelisted binaries are reported or denied, and that normal behavior resumes after the loader exits. Do not read `trace_pipe` in another terminal while the test runs.

```sh
cd guardian
sudo python3 test/test_guardian.py loader/bin/loader
```

## Repository layout

```
supervisors/
├── toll/
│   ├── module/src/     eBPF program
│   ├── loader/src/     userspace loader
│   ├── loader/rsrc/    IP whitelists
│   ├── test/
│   └── Makefile
├── guardian/
│   ├── module/src/     eBPF program
│   ├── loader/src/     userspace loader
│   ├── loader/rsrc/    binary whitelist
│   ├── test/
│   └── Makefile
└── Retrofitting_Runtime_Security_onto_Legacy_Embedded_Linux_with_Modular_eBPF_Supervisors.pdf
```

## Limitations

- Tested on a workstation only. Evaluation on embedded hardware and against real exploits has not been performed.
- Guardian does not prevent memory corruption or control-flow hijacking. It only blocks the resulting `mmap`, `mprotect` and `execve` calls.
- Inode matching does not survive reflashing and does not prevent execution of a whitelisted binary by an attacker.
- Toll filters IPv4 by address only. It does not handle IPv6, ports or protocols.
- Whitelists are read at startup. Changes require restarting the loader.

## License

Released under the [GNU General Public License v3.0](LICENSE).