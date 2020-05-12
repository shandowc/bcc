#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# funclatency   Time functions and print latency as a histogram.
#               For Linux, uses BCC, eBPF.
#
# USAGE: funclatency [-h] [-p PID] [-i INTERVAL] [-T] [-u] [-m] [-F] [-r] [-v]
#                    pattern
#
# Run "funclatency -h" for full usage.
#
# The pattern is a string with optional '*' wildcards, similar to file
# globbing. If you'd prefer to use regular expressions, use the -r option.
#
# Currently nested or recursive functions are not supported properly, and
# timestamps will be overwritten, creating dubious output. Try to match single
# functions, or groups of functions that run at the same stack layer, and
# don't ultimately call each other.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg       Created this.
# 06-Oct-2016   Sasha Goldshtein    Added user function support.
# 12-May-2020   Shandowc            Created gofunclatency.

from __future__ import print_function
from bcc import BPF, lib
from time import sleep, strftime
import argparse
import signal

# arguments
examples = """examples:
    ./funclatency do_sys_open       # time the do_sys_open() kernel function
    ./funclatency c:read            # time the read() C library function
    ./funclatency -u vfs_read       # time vfs_read(), in microseconds
    ./funclatency -m do_nanosleep   # time do_nanosleep(), in milliseconds
    ./funclatency -i 2 -d 10 c:open # output every 2 seconds, for duration 10s
    ./funclatency -mTi 5 vfs_read   # output every 5 seconds, with timestamps
    ./funclatency -p 181 vfs_read   # time process 181 only
    ./funclatency 'vfs_fstat*'      # time both vfs_fstat() and vfs_fstatat()
    ./funclatency 'c:*printf'       # time the *printf family of functions
    ./funclatency -F 'vfs_r*'       # show one histogram per matched function
"""
parser = argparse.ArgumentParser(
    description="Time functions and print latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int,
    help="trace this PID only")
parser.add_argument("-i", "--interval", type=int,
    help="summary interval, in seconds")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="microsecond histogram")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-F", "--function", action="store_true",
    help="show a separate histogram per function")
parser.add_argument("-v", "--verbose", action="store_true",
    help="print the BPF program (for debugging purposes)")
parser.add_argument("pattern", type=str,
    help="search expression for functions")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if args.duration and not args.interval:
    args.interval = args.duration
if not args.interval:
    args.interval = 99999999

def bail(error):
    print("Error: " + error)
    exit(1)

parts = args.pattern.encode('utf8').split(b':')
if len(parts) == 2:
    library = parts[0]
    libpath = BPF.find_library(library) or BPF.find_exe(library)
    if not libpath:
        bail("can't resolve library %s" % library)
    library = libpath
    pattern = parts[1]
else:
    bail("unrecognized pattern format '%s'" % pattern)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

typedef struct ip_pid {
    u64 ip;
    u64 pid;
} ip_pid_t;

typedef struct hist_key {
    ip_pid_t key;
    u64 slot;
} hist_key_t;

BPF_HASH(tls, u32);
BPF_HASH(start);
STORAGE

int log_goroutine_id(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 goid = 0;
    void* g;
    bpf_probe_read(&g, sizeof(g), (void*)(ctx->sp+8));
    bpf_probe_read(&goid, sizeof(goid), g+152);
    tls.update(&pid, &goid);
    return 0;
}

int trace_func_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;
    FILTER

    u64* pgoid = tls.lookup(&pid);
    if (!pgoid) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    
    ENTRYSTORE
    start.update(pgoid, &ts);

    return 0;
}

int trace_func_return(struct pt_regs *ctx)
{
    u64 *tsp, delta;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    // calculate delta time
    u64* pgoid = tls.lookup(&pid);
    if (!pgoid) {
        return 0;
    }

    tsp = start.lookup(pgoid);
    if (!tsp) {
        return 0;   // missed start
    }
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(pgoid);
    FACTOR

    // store as histogram
    STORE

    return 0;
}
"""

# do we need to store the IP and pid for each invocation?
need_key = args.function or (library and not args.pid)

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (tgid != %d) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
elif args.microseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    label = "nsecs"
if need_key:
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HASH(ipaddr, u32);\n' +
        'BPF_HISTOGRAM(dist, hist_key_t);')
    # stash the IP on entry, as on return it's kretprobe_trampoline:
    bpf_text = bpf_text.replace('ENTRYSTORE',
        'u64 ip = PT_REGS_IP(ctx); ipaddr.update(&pid, &ip);')
    pid = '-1' if not library else 'tgid'
    bpf_text = bpf_text.replace('STORE',
        """
    u64 ip, *ipp = ipaddr.lookup(&pid);
    if (ipp) {
        ip = *ipp;
        hist_key_t key;
        key.key.ip = ip;
        key.key.pid = %s;
        key.slot = bpf_log2l(delta);
        dist.increment(key);
        ipaddr.delete(&pid);
    }
        """ % pid)
else:
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    bpf_text = bpf_text.replace('ENTRYSTORE', '')
    bpf_text = bpf_text.replace('STORE',
        'dist.increment(bpf_log2l(delta));')
if args.verbose or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# signal handler
def signal_ignore(signal, frame):
    print()

# load BPF program
b = BPF(text=bpf_text)

import struct
import mmap
from collections import namedtuple

ElfFileHeader = namedtuple('ElfFileHeader', (
    'e_ident',
    'e_type',
    'e_machine',
    'e_version',
    'e_entry',
    'e_phoff',
    'e_shoff',
    'e_flags',
    'e_ehsize',
    'e_phentsize',
    'e_phnum',
    'e_shentsize',
    'e_shnum',
    'e_shstrndx',
))

SectionHeader = namedtuple('SectionHeader', (
    'sh_name',
    'sh_type',
    'sh_flags',
    'sh_addr',
    'sh_offset',
    'sh_size',
    'sh_link',
    'sh_info',
    'sh_addralign',
    'sh_entsize',
))

ProgramHeader = namedtuple('ProgramHeader', (
    'p_type',
    'p_offset',
    'p_vaddr',
    'p_paddr',
    'p_filesz',
    'p_memsz',
    'p_flags',
    'p_align',
))

SHT_SYMTAB = 2
SHT_STRTAB = 3
PT_LOAD = 1

class Symbol(object):
    
    def __init__(self, name, offset, vaddr, size):
        self.name = name
        self.offset = offset
        self.vaddr = vaddr
        self.size = size

class Elfile(object):

    def __init__(self, filename):
        f = open(filename, 'rb')
        self._buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        self._init_templates()

        fh = ElfFileHeader._make(self._extract(0, ElfFileHeader))
        self.file_header = fh
        self.sections = self._extract_array(fh.e_shoff, fh.e_shentsize, fh.e_shnum, SectionHeader)
        self.programs = self._extract_array(fh.e_phoff, fh.e_phentsize, fh.e_phnum, ProgramHeader)
        strsec = self.sections[self.file_header.e_shstrndx]
        self.shstrtab = self.get_data(strsec.sh_offset, strsec.sh_size)

        syms = []
        for sec in self.sections:
            name = str_name(self.shstrtab, sec.sh_name)
            if name == b'.strtab':
                self.strtab = self.get_data(sec.sh_offset, sec.sh_size)
            elif SHT_SYMTAB == sec.sh_type:
                num = sec.sh_size // sec.sh_entsize
                syms.extend(self._extract_array(sec.sh_offset, sec.sh_entsize, num, self.SymEntryClass))
        symdict = {}
        for sym in syms:
            sname = self.sym_str_name(sym.st_name)
            symdict[sname] = sym
        self.symdict = symdict

    def get_sym(self, symname):
        sym = self.symdict.get(symname, None)
        if sym is None:
            return None
        name = self.sym_str_name(sym.st_name)
        sec = self.sections[sym.st_shndx]
        offset = (sym.st_value - sec.sh_addr) + sec.sh_offset
        return Symbol(name, offset, sym.st_value, sym.st_size)

    def section_str_name(self, sh_name):
        return str_name(self.shstrtab, sh_name)

    def sym_str_name(self, sy_name):
        return str_name(self.strtab, sy_name)

    def get_data(self, offset, size):
        return self._buf[offset:offset+size]

    def _extract_array(self, offset, entsize, num, typ):
        arr = []
        for off in range(offset, offset + entsize * num, entsize):
            sec = typ._make(self._extract(off, typ))
            arr.append(sec)
        return arr

    def _extract(self, offset, typ):
        templ = self._templs[typ]
        return struct.unpack(templ, self.get_data(offset, struct.calcsize(templ)))

    def _init_templates(self):
        class_endian = self._buf[4:6]
        file_templ = {
            b'\1\1': '<16sHHIIIIIHHHHHH',
            b'\2\1': '<16sHHIQQQIHHHHHH',
            b'\1\2': '>16sHHIIIIIHHHHHH',
            b'\2\2': '>16sHHIQQQIHHHHHH',
        }[class_endian]
        section_templ = {
            b'\1\1': '<10I',
            b'\2\1': '<2I4Q2I2Q',
            b'\1\2': '>10I',
            b'\2\2': '>2I4Q2I2Q',
        }[class_endian]
        program_templ = {
            b'\1\1': '<8I',
            b'\2\1': '<2I6Q',
            b'\1\2': '>8I',
            b'\2\2': '>2I6Q',
        }[class_endian]
        symbol_templ = {
            b'\1\1': '<3I2BH',
            b'\2\1': '<I2BHQQ',
            b'\1\2': '>3I2BH',
            b'\2\2': '>I2BHQQ',
        }[class_endian]
        self.SymEntryClass = {
            b'\1': namedtuple('SymEntry', (
                'st_name',
                'st_value',
                'st_size',
                'st_info',
                'st_other',
                'st_shndx',
            )),
            b'\2': namedtuple('SymEntry', (
                'st_name',
                'st_info',
                'st_other',
                'st_shndx',
                'st_value',
                'st_size',
            )),
        }[class_endian[:1]]
        self._templs = {
            ElfFileHeader:          file_templ,
            SectionHeader:          section_templ,
            ProgramHeader:          program_templ,
            self.SymEntryClass:     symbol_templ,
        }

def str_name(strtab, nname):
    s = strtab[nname:]
    m = s.index(b'\0')
    return s[:m]

def attach_uprobe_by_addr(bpfo, path=b"", addr=None, fn_name=b""):
    bpfo._check_probe_quota(1)
    fn = bpfo.load_func(fn_name, BPF.KPROBE)
    ev_name = bpfo._get_uprobe_evname(b"p", path, addr, -1)
    fd = lib.bpf_attach_uprobe(fn.fd, 0, ev_name, path, addr, -1)
    if fd < 0:
        raise Exception("Failed to attach BPF to uprobe")
    bpfo._add_uprobe_fd(ev_name, fd)
    return bpfo

def safe_readline(proc):
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.rstrip()
        yield line

def attach_uprobe_for_latency(path=b'', sym=b''):
    import subprocess
    import re
    symbol = Elfile(path).get_sym(sym)
    cmd = "objdump -d %s --start-address=%d --stop-address=%d" % (path.decode('utf8'), symbol.vaddr, symbol.vaddr+symbol.size)
    proc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE)
    start_re_str = b'^([0-9a-f]+ <' + re.escape(sym) + b'>:)$'
    re_start = re.compile(start_re_str)
    re_func = re.compile(b'^([0-9a-f]+ <[^>]+>:)$')
    re_ret = re.compile(b'^\\s*([0-9a-f]+):\\s+[0-9a-f]+\\s+ret')
    raddrs = []
    saddr = None
    for line in safe_readline(proc):
        if re_start.match(line):
            saddr = int(re_start.findall(line)[0].split()[0], 16)
            continue
        if saddr is not None:
            if re_func.match(line):
                break
            raddrs.extend([int(x, 16) for x in re_ret.findall(line)])
    if len(raddrs) == 0:
        print("err: can not find symbol addrs")
        exit()

    b.attach_uprobe(name=path, sym=b'runtime.execute', fn_name="log_goroutine_id", pid=args.pid or -1)
    attach_uprobe_by_addr(b, path, addr=symbol.offset, fn_name="trace_func_entry")
    for raddr in raddrs:
        off = raddr - saddr
        attach_uprobe_by_addr(b, path, addr=symbol.offset+off, fn_name="trace_func_return")

# attach probes
attach_uprobe_for_latency(library, pattern)
matched = b.num_open_uprobes()

if matched == 0:
    print("0 functions matched by \"%s\". Exiting." % args.pattern)
    exit()

# header
print("Tracing for \"%s\"... Hit Ctrl-C to end." %
    (args.pattern))

# output
def print_section(key):
    if not library:
        return BPF.sym(key[0], -1)
    else:
        return "%s [%d]" % (BPF.sym(key[0], key[1]), key[1])

exiting = 0 if args.interval else 1
seconds = 0
dist = b.get_table("dist")

while (1):
    try:
        sleep(args.interval)
        seconds += args.interval
    except KeyboardInterrupt:
        exiting = 1
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)
    if args.duration and seconds >= args.duration:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    if need_key:
        dist.print_log2_hist(label, "Function", section_print_fn=print_section,
            bucket_fn=lambda k: (k.ip, k.pid))
    else:
        dist.print_log2_hist(label)
    dist.clear()

    if exiting:
        print("Detaching...")
        exit()
