#!/usr/bin/env python3
"""
Nominal-case tests for the toll eBPF module and loader. Standard library only.

  unit         Pulls module.bpf.o out of the loader binary (the skeleton embeds
               it), loads it, and pushes a few hand-made packets through
               on_arrival / on_departure. Nothing is attached to any interface.

  integration  Runs the loader in a throwaway network namespace on a virtual
               interface named enp5s0 and pings through it. Your real network
               and whitelist files are never touched.

Usage (as root, from the project root):
  sudo python3 test/test_toll.py loader/bin/loader
  sudo python3 test/test_toll.py loader/bin/loader --only unit
  sudo python3 test/test_toll.py loader/bin/loader --only integration
"""

import argparse
import ctypes
import ctypes.util
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

TC_ACT_OK = 0
TC_ACT_SHOT = 2


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


class Report:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, name, cond, detail=""):
        print(f"  {'ok  ' if cond else 'FAIL'}  {name}{'' if cond or not detail else '  ' + detail}")
        if cond:
            self.passed += 1
        else:
            self.failed += 1

    def summary(self, label):
        print(f"{label}: {self.passed}/{self.passed + self.failed} passed")
        return self.failed == 0


# ============================================================ unit test ====

class TestRunOpts(ctypes.Structure):
    # struct bpf_test_run_opts (libbpf 1.x)
    _fields_ = [("sz", ctypes.c_size_t),
                ("data_in", ctypes.c_void_p), ("data_out", ctypes.c_void_p),
                ("data_size_in", ctypes.c_uint32), ("data_size_out", ctypes.c_uint32),
                ("ctx_in", ctypes.c_void_p), ("ctx_out", ctypes.c_void_p),
                ("ctx_size_in", ctypes.c_uint32), ("ctx_size_out", ctypes.c_uint32),
                ("retval", ctypes.c_uint32), ("repeat", ctypes.c_int),
                ("duration", ctypes.c_uint32), ("flags", ctypes.c_uint32),
                ("cpu", ctypes.c_uint32), ("batch_size", ctypes.c_uint32)]


class BtfType(ctypes.Structure):
    _fields_ = [("name_off", ctypes.c_uint32), ("info", ctypes.c_uint32), ("size", ctypes.c_uint32)]


class BtfVarSecinfo(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("offset", ctypes.c_uint32), ("size", ctypes.c_uint32)]


PRINT_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p)


def extract_module(loader_path, outdir):
    """The skeleton embeds module.bpf.o in the loader: find that BPF ELF."""
    blob = open(loader_path, "rb").read()
    pos = blob.find(b"\x7fELF", 1)
    while pos != -1:
        hdr = blob[pos:pos + 64]
        if len(hdr) == 64 and hdr[4] == 2 and struct.unpack_from("<H", hdr, 18)[0] == 247:  # EM_BPF
            shoff = struct.unpack_from("<Q", hdr, 40)[0]
            shentsize, shnum = struct.unpack_from("<HH", hdr, 58)
            path = os.path.join(outdir, "module.bpf.o")
            open(path, "wb").write(blob[pos:pos + shoff + shentsize * shnum])
            return path
        pos = blob.find(b"\x7fELF", pos + 1)
    die(f"no embedded BPF object in {loader_path}")


class Module:
    def __init__(self, obj_path):
        lib = ctypes.CDLL(ctypes.util.find_library("bpf") or "libbpf.so.1")
        vp, cp, i = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
        for fn, res, argt in [
            ("libbpf_set_print", vp, [PRINT_FN]),
            ("bpf_object__open_file", vp, [cp, vp]),
            ("bpf_object__load", i, [vp]),
            ("bpf_object__find_program_by_name", vp, [vp, cp]),
            ("bpf_object__next_map", vp, [vp, vp]),
            ("bpf_object__btf", vp, [vp]),
            ("bpf_program__fd", i, [vp]),
            ("bpf_map__name", cp, [vp]),
            ("bpf_map__fd", i, [vp]),
            ("bpf_map__value_size", ctypes.c_uint32, [vp]),
            ("bpf_map_lookup_elem", i, [i, vp, vp]),
            ("bpf_map_update_elem", i, [i, vp, vp, ctypes.c_uint64]),
            ("bpf_prog_test_run_opts", i, [i, ctypes.POINTER(TestRunOpts)]),
            ("btf__find_by_name_kind", ctypes.c_int32, [vp, cp, ctypes.c_uint32]),
            ("btf__type_by_id", ctypes.POINTER(BtfType), [vp, ctypes.c_uint32]),
            ("btf__name_by_offset", cp, [vp, ctypes.c_uint32]),
        ]:
            getattr(lib, fn).restype, getattr(lib, fn).argtypes = res, argt
        self.lib = lib
        self._quiet = PRINT_FN(lambda *a: 0)
        lib.libbpf_set_print(self._quiet)

        obj = lib.bpf_object__open_file(obj_path.encode(), None)
        if not obj or lib.bpf_object__load(obj) != 0:
            die("module failed to load (verifier rejected it, or not root?)")
        self.fd = {p: lib.bpf_program__fd(lib.bpf_object__find_program_by_name(obj, p.encode()))
                   for p in ("on_arrival", "on_departure")}

        # The globals live in the .bss map; get their offsets from BTF.
        m = lib.bpf_object__next_map(obj, None)
        while m and not lib.bpf_map__name(m).endswith(b".bss"):
            m = lib.bpf_object__next_map(obj, m)
        self.bss_fd, self.bss_size = lib.bpf_map__fd(m), lib.bpf_map__value_size(m)
        btf = lib.bpf_object__btf(obj)
        sec = lib.btf__type_by_id(btf, lib.btf__find_by_name_kind(btf, b".bss", 15)).contents
        infos = ctypes.cast(ctypes.addressof(sec) + ctypes.sizeof(BtfType), ctypes.POINTER(BtfVarSecinfo))
        self.off = {}
        for k in range(sec.info & 0xFFFF):
            name = lib.btf__name_by_offset(btf, lib.btf__type_by_id(btf, infos[k].type).contents.name_off)
            self.off[name.decode()] = infos[k].offset

    def set_list(self, name, ips):
        key = ctypes.c_uint32(0)
        buf = ctypes.create_string_buffer(self.bss_size)
        self.lib.bpf_map_lookup_elem(self.bss_fd, ctypes.byref(key), buf)
        data = bytearray(buf.raw)
        for idx, ip in enumerate(ips):
            o = self.off[name] + 4 * idx
            data[o:o + 4] = socket.inet_aton(ip)   # network byte order, like inet_pton
        o = self.off[name + "_count"]
        data[o:o + 4] = struct.pack("=I", len(ips))
        buf = ctypes.create_string_buffer(bytes(data), self.bss_size)
        self.lib.bpf_map_update_elem(self.bss_fd, ctypes.byref(key), buf, 0)

    def run(self, prog, pkt):
        buf = ctypes.create_string_buffer(pkt, len(pkt))
        opts = TestRunOpts(sz=ctypes.sizeof(TestRunOpts), data_in=ctypes.cast(buf, ctypes.c_void_p),
                           data_size_in=len(pkt), repeat=1)
        if self.lib.bpf_prog_test_run_opts(self.fd[prog], ctypes.byref(opts)):
            die("bpf_prog_test_run_opts failed")
        return opts.retval


ETH = bytes.fromhex("020000000001" "020000000002")


def ipv4(src, dst):
    return (ETH + b"\x08\x00"
            + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 1, 0,
                          socket.inet_aton(src), socket.inet_aton(dst))
            + b"\x08" + b"\x00" * 7)


def arp():
    return (ETH + b"\x08\x06").ljust(42, b"\x00")


def unit_test(loader):
    print("=== unit test ===")
    with tempfile.TemporaryDirectory() as tmp:
        mod = Module(extract_module(loader, tmp))

    # Asymmetric IPs on purpose: 1.1.1.1 would hide a byte-order bug.
    mod.set_list("whitelisted_arrivals", ["192.168.1.10"])
    mod.set_list("whitelisted_departures", ["10.20.30.40"])
    ME = "10.0.0.1"

    rep = Report()
    name = {TC_ACT_OK: "PASS", TC_ACT_SHOT: "DROP"}

    def expect(desc, prog, pkt, want):
        got = mod.run(prog, pkt)
        rep.check(desc, got == want, f"expected {name.get(want)}, got {name.get(got, got)}")

    expect("in:  whitelisted source passes",      "on_arrival",   ipv4("192.168.1.10", ME), TC_ACT_OK)
    expect("in:  unknown source is dropped",      "on_arrival",   ipv4("203.0.113.9", ME),  TC_ACT_SHOT)
    expect("out: whitelisted destination passes", "on_departure", ipv4(ME, "10.20.30.40"), TC_ACT_OK)
    expect("out: unknown destination is dropped", "on_departure", ipv4(ME, "203.0.113.9"), TC_ACT_SHOT)
    expect("ARP is not touched",                  "on_arrival",   arp(),                   TC_ACT_OK)
    return rep.summary("unit test")


# ===================================================== integration test ====
#
#   [toll_dut] enp5s0 10.99.0.1  <== veth ==>  peer0 [toll_peer]
#                                              10.99.0.2 whitelisted both ways
#                                              10.99.0.3 not whitelisted

DUT, PEER = "toll_dut", "toll_peer"


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def ping(ns, src, dst):
    return sh("ip", "netns", "exec", ns, "ping", "-n", "-q", "-c", "2", "-i", "0.2",
              "-W", "1", "-I", src, dst).returncode == 0


def whitelist_paths(loader):
    """Read the whitelist paths compiled into the loader."""
    strings = [s.decode() for s in re.findall(rb"[\x20-\x7e]{4,}(?=\x00)", open(loader, "rb").read())]
    txt = [s for s in strings if s.endswith(".txt") and "%" not in s]
    arr = [s for s in txt if "arriv" in s]
    dep = [s for s in txt if "depart" in s]
    if len(arr) != 1 or len(dep) != 1:
        die(f"can't find the whitelist paths in the loader (found {txt})")
    if os.path.isabs(arr[0]) or os.path.isabs(dep[0]):
        die("loader uses absolute whitelist paths; the test would overwrite your real files")
    return arr[0], dep[0]


def integration_test(loader):
    print("\n=== integration test ===")
    loader = os.path.abspath(loader)
    arr_path, dep_path = whitelist_paths(loader)

    # Run the loader from a temp dir where its relative paths lead to our test lists.
    work = tempfile.mkdtemp(prefix="toll_test.")
    depth = max(p.split("/").count("..") for p in (arr_path, dep_path))
    run_dir = os.path.join(work, *(["d"] * depth), "run")
    for rel in (arr_path, dep_path):
        full = os.path.normpath(os.path.join(run_dir, rel))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").write("10.99.0.2\n")

    for ns in (DUT, PEER):
        sh("ip", "netns", "del", ns)
        sh("ip", "netns", "add", ns)
    sh("ip", "link", "add", "enp5s0", "netns", DUT, "type", "veth", "peer", "name", "peer0", "netns", PEER)
    for ns, dev, ips in ((DUT, "enp5s0", ["10.99.0.1"]), (PEER, "peer0", ["10.99.0.2", "10.99.0.3"])):
        sh("ip", "-n", ns, "link", "set", "lo", "up")
        sh("ip", "-n", ns, "link", "set", dev, "up")
        for ip in ips:
            sh("ip", "-n", ns, "addr", "add", f"{ip}/24", "dev", dev)

    rep = Report()
    log_path = os.path.join(work, "loader.log")
    proc = None
    try:
        log = open(log_path, "w")
        proc = subprocess.Popen(["ip", "netns", "exec", DUT, "stdbuf", "-oL", loader],
                                cwd=run_dir, stdout=log, stderr=subprocess.STDOUT)
        started = False
        for _ in range(50):
            if "Running" in open(log_path).read():
                started = True
                break
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        rep.check("loader starts and attaches to enp5s0", started)
        if not started:
            print("----- loader output -----\n" + open(log_path).read())
            return rep.summary("integration test")

        rep.check("ping out to whitelisted 10.99.0.2 works",  ping(DUT, "10.99.0.1", "10.99.0.2"))
        rep.check("ping out to 10.99.0.3 is blocked",         not ping(DUT, "10.99.0.1", "10.99.0.3"))
        rep.check("ping in from whitelisted 10.99.0.2 works", ping(PEER, "10.99.0.2", "10.99.0.1"))
        rep.check("ping in from 10.99.0.3 is blocked",        not ping(PEER, "10.99.0.3", "10.99.0.1"))

        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=3)
        proc = None
        rep.check("after Ctrl-C, 10.99.0.3 is reachable again", ping(DUT, "10.99.0.1", "10.99.0.3"))
        return rep.summary("integration test")
    finally:
        if proc:
            proc.kill()
            proc.wait()
        for ns in (DUT, PEER):
            sh("ip", "netns", "del", ns)
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Nominal-case tests for the toll module and loader.")
    ap.add_argument("loader", help="compiled loader binary, e.g. loader/bin/loader")
    ap.add_argument("--only", choices=["unit", "integration"])
    args = ap.parse_args()
    if os.geteuid() != 0:
        die("run as root")
    if not os.access(args.loader, os.X_OK):
        die(f"{args.loader} is not an executable")

    ok = True
    if args.only in (None, "unit"):
        ok &= unit_test(args.loader)
    if args.only in (None, "integration"):
        ok &= integration_test(args.loader)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()