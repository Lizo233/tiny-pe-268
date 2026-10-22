"""Build all targets.  Usage:  python gen/build.py

Produces (into ../build):
  hello-268.exe        268 B   prints "hello world"
  hello-echo-arg.exe   268 B   echo semantics: prints its command-line argument
  hello-echo-fold.exe  268 B   filter: stdin -> stdout (code folded into header)
  hello-echo-stdin.exe 302 B   filter: stdin -> stdout (contiguous, over budget)

Every target shares the same degenerate PE header:
  e_lfanew = 4, NumberOfSections = 0, SizeOfOptionalHeader = 8,
  SectionAlignment = FileAlignment = 4, SizeOfImage = 0x2000,
  NumberOfRvaAndSizes = 0   -> no import directory, imports resolved by hand.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mini_asm import Asm

IMAGE_BASE = 0x400000
BUF = 0x400800          # writable zero-fill area inside SizeOfImage; costs 0 file bytes
MUL = 33
MIN_SIZE = 268
SIZE_OF_IMAGE = 0x2000
MSG_OFF = 0x20          # "hello world" lives in SizeOfCode/SizeOfInitData/...

# header layout the loader actually reads
CODE_OFF = 0x7C         # 0x1C + 0x60: last field it reads is dir count at opt+0x5C


def h(name):
    """h = h*33 + c over the export name.

    The scan loop multiplies *before* testing for the NUL terminator, so the
    terminator costs one extra multiply; pre-multiplying the constant keeps the
    loop one instruction shorter.  (Forgetting this makes every lookup miss --
    the symptom is a call to address 0, i.e. an immediate 0xC0000005.)
    """
    v = 0
    for c in name:
        v = (v * MUL + c) & 0xFFFFFFFF
    return (v * MUL) & 0xFFFFFFFF


H_WRITEFILE = h(b'WriteFile')
H_READFILE = h(b'ReadFile')
H_GETCMDLINE = h(b'GetCommandLineA')


# --------------------------------------------------------------------------
# shared code fragments
# --------------------------------------------------------------------------
def preamble(a, r):
    """sub esp,0x10 ; PEB -> Ldr -> kernel32 ; export dir -> 4 table pointers.

    Stack slots (E = esp after the sub):
      [E+0] first match   [E+4] second match   [E+8] counter   [E+12] scratch
    """
    a.emit(r, 0x83, 0xEC, 0x10)                  # sub esp, 0x10
    a.emit(r, 0x64, 0xA1, 0x30, 0, 0, 0)         # mov eax, fs:[0x30]      TEB->PEB
    a.emit(r, 0x8B, 0x40, 0x0C)                  # PEB->Ldr
    a.emit(r, 0x8B, 0x40, 0x0C)                  # Ldr->InLoadOrderModuleList
    a.emit(r, 0x8B, 0x00)                        # -> ntdll
    a.emit(r, 0x8B, 0x00)                        # -> kernel32
    a.emit(r, 0x8B, 0x70, 0x18)                  # esi = DllBase
    a.emit(r, 0x8B, 0x46, 0x3C)                  # e_lfanew
    a.emit(r, 0x8B, 0x44, 0x06, 0x78)            # dir[0] = export table RVA
    a.emit(r, 0x03, 0xC6)                        # -> VA
    a.emit(r, 0x8B, 0x58, 0x20)                  # ebx = AddressOfNames
    a.emit(r, 0x03, 0xDE)
    a.emit(r, 0x8B, 0x78, 0x24)                  # edi = AddressOfNameOrdinals
    a.emit(r, 0x03, 0xFE)
    a.emit(r, 0x8B, 0x50, 0x1C)                  # edx = AddressOfFunctions
    a.emit(r, 0x03, 0xD6)
    a.emit(r, 0x8B, 0x48, 0x18)                  # ecx = NumberOfNames
    a.emit(r, 0x89, 0x4C, 0x24, 0x08)            # [esp+8] = counter
    a.emit(r, 0x89, 0xDD)                        # ebp = ebx (names cursor)


def scan_head(a, r, h1, h2):
    """Walk the name table once, matching two hashes; stores ptrs in [esp],[esp+4]."""
    a.label('next', r)
    a.emit(r, 0x8B, 0x5D, 0x00)                  # mov ebx, [ebp]
    a.emit(r, 0x03, 0xDE)                        # add ebx, esi
    a.emit(r, 0x31, 0xC0)                        # xor eax, eax
    a.label('hash', r)
    a.emit(r, 0x6B, 0xC0, 0x21)                  # imul eax, eax, 33
    a.emit(r, 0x0F, 0xB6, 0x0B)                  # movzx ecx, byte [ebx]
    a.emit(r, 0x03, 0xC1)                        # add eax, ecx
    a.emit(r, 0x43)                              # inc ebx
    a.emit(r, 0x85, 0xC9)                        # test ecx, ecx
    a.j8(r, 0x75, 'hash')
    a.emit(r, 0x3D, *struct.pack('<I', h1))
    a.j8(r, 0x74, 'f1')
    a.emit(r, 0x3D, *struct.pack('<I', h2))
    a.j8(r, 0x74, 'f2')


def scan_adv(a, r):
    """Advance to the next name; falls through to the caller's 'done'.

    Call order matters: scan_head -> scan_adv -> (caller's done code) ->
    scan_blocks.  If the match blocks sat directly after adv, adv's `jnz`
    falling through would execute them with a garbage EAX.
    """
    a.label('adv', r)
    a.emit(r, 0x83, 0xC5, 0x04)                  # add ebp, 4
    a.emit(r, 0x83, 0xC7, 0x02)                  # add edi, 2
    a.emit(r, 0xFF, 0x4C, 0x24, 0x08)            # dec dword [esp+8]
    a.j8(r, 0x75, 'next')


def scan_blocks(a, r):
    """Match handlers; store the resolved pointer into [esp] / [esp+4]."""
    a.label('f1', r)
    a.emit(r, 0x31, 0xDB)                        # xor ebx, ebx  -> slot 0
    a.j8(r, 0xEB, 'found')
    a.label('f2', r)
    a.emit(r, 0x6A, 0x04)                        # push 4
    a.emit(r, 0x5B)                              # pop ebx       -> slot 4
    a.j8(r, 0xEB, 'found')
    a.label('found', r)
    a.emit(r, 0x0F, 0xB7, 0x07)                  # movzx eax, word [edi]
    a.emit(r, 0x8B, 0x04, 0x82)                  # mov eax, [edx+eax*4]   EAT
    a.emit(r, 0x03, 0xC6)                        # add eax, esi
    a.emit(r, 0x89, 0x04, 0x1C)                  # mov [esp+ebx], eax
    a.j8(r, 0xEB, 'adv')


def pe_file(regions, regions_code, entry, size=MIN_SIZE):
    """Assemble the degenerate PE around the emitted regions."""
    f = bytearray(max(size, MIN_SIZE))

    def put(va, b):
        off = va - IMAGE_BASE
        f[off:off + len(b)] = b

    put(0x400000, b'MZ')
    put(0x400000 + 0x3C, struct.pack('<I', 4))          # e_lfanew = 4
    put(0x400004, b'PE\x00\x00')
    put(0x400008, struct.pack('<HHIIIHH', 0x14C, 0, 0x6A803331, 0, 0, 8, 0x0002))
    o = 0x40001C
    put(o + 0x00, struct.pack('<H', 0x10B))             # PE32
    put(o + 0x10, struct.pack('<I', entry))
    put(o + 0x1C, struct.pack('<I', IMAGE_BASE))
    put(o + 0x20, struct.pack('<I', 4))                 # SectionAlignment
    put(o + 0x24, struct.pack('<I', 4))                 # FileAlignment
    put(o + 0x30, struct.pack('<HH', 5, 0))             # Subsystem version
    put(o + 0x38, struct.pack('<I', SIZE_OF_IMAGE))
    put(o + 0x3C, struct.pack('<I', 0x30))              # SizeOfHeaders
    put(o + 0x44, struct.pack('<HH', 3, 0))             # console
    put(o + 0x5C, struct.pack('<I', 0))                 # NumberOfRvaAndSizes = 0

    for name, (va, _) in regions.items():
        put(IMAGE_BASE + va, regions_code[name])
    return bytes(f)


# --------------------------------------------------------------------------
# target 1: hello-268 -- print a fixed string
# --------------------------------------------------------------------------
def build_hello():
    R = {'main': (0x7C, 144)}
    a = Asm(R)
    preamble(a, 'main')
    # single-function scan (only WriteFile needed)
    a.label('next2', 'main')
    a.emit('main', 0x8B, 0x5D, 0x00)
    a.emit('main', 0x03, 0xDE)
    a.emit('main', 0x31, 0xC0)
    a.label('hash2', 'main')
    a.emit('main', 0x6B, 0xC0, 0x21)
    a.emit('main', 0x0F, 0xB6, 0x0B)
    a.emit('main', 0x03, 0xC1)
    a.emit('main', 0x43)
    a.emit('main', 0x85, 0xC9)
    a.j8('main', 0x75, 'hash2')
    a.emit('main', 0x3D, *struct.pack('<I', H_WRITEFILE))
    a.j8('main', 0x74, 'found2')
    a.label('adv2', 'main')
    a.emit('main', 0x83, 0xC5, 0x04)
    a.emit('main', 0x83, 0xC7, 0x02)
    a.emit('main', 0xFF, 0x4C, 0x24, 0x08)
    a.j8('main', 0x75, 'next2')
    a.j8('main', 0xEB, 'done2')
    a.label('found2', 'main')
    a.emit('main', 0x0F, 0xB7, 0x07)
    a.emit('main', 0x8B, 0x04, 0x82)
    a.emit('main', 0x03, 0xC6)
    a.emit('main', 0x89, 0x04, 0x24)
    a.j8('main', 0xEB, 'adv2')
    a.label('done2', 'main')
    a.emit('main', 0x6A, 0x00)                   # lpOverlapped
    a.emit('main', 0x6A, 0x00)                   # lpNumberOfBytesWritten
    a.emit('main', 0x6A, 11)                     # nBytes
    a.emit('main', 0x68, *struct.pack('<I', IMAGE_BASE + MSG_OFF))
    a.emit('main', 0x6A, 0xF5)                   # -11 = STD_OUTPUT_HANDLE
    a.emit('main', 0xFF, 0x54, 0x24, 0x14)       # call [esp+20] WriteFile
    a.emit('main', 0x83, 0xC4, 0x10)             # add esp, 16
    a.emit('main', 0x31, 0xC0)
    a.emit('main', 0xC3)
    reg = a.finalize()
    data = pe_file(R, reg, 0x7C)
    data = bytearray(data)
    data[MSG_OFF:MSG_OFF + 11] = b'hello world'
    return bytes(data), reg


# --------------------------------------------------------------------------
# target 2: echo-arg -- real echo, 268 B, code folded into header holes
# --------------------------------------------------------------------------
def build_echo_arg():
    R = {'h1': (0x00C, 12), 'h2': (0x020, 12), 'h3': (0x030, 8),
         'h4': (0x044, 8), 'main': (0x07C, 144)}
    a = Asm(R)
    preamble(a, 'main')
    # two-hash scan: GetCommandLineA sorts before WriteFile -> found first
    a.label('next', 'main')
    a.emit('main', 0x8B, 0x5D, 0x00)
    a.emit('main', 0x03, 0xDE)
    a.emit('main', 0x31, 0xC0)
    a.label('hash', 'main')
    a.emit('main', 0x6B, 0xC0, 0x21)
    a.emit('main', 0x0F, 0xB6, 0x0B)
    a.emit('main', 0x03, 0xC1)
    a.emit('main', 0x43)
    a.emit('main', 0x85, 0xC9)
    a.j8('main', 0x75, 'hash')
    a.emit('main', 0x3D, *struct.pack('<I', H_GETCMDLINE))
    a.j8('main', 0x74, 'f1')
    a.emit('main', 0x3D, *struct.pack('<I', H_WRITEFILE))
    a.j8('main', 0x74, 'f2')
    a.label('adv', 'main')
    a.emit('main', 0x83, 0xC5, 0x04)
    a.emit('main', 0x83, 0xC7, 0x02)
    a.emit('main', 0xFF, 0x4C, 0x24, 0x08)
    a.j8('main', 0x75, 'next')
    # body: no-arg call is 3 bytes because GetCommandLineA is at [esp]
    a.emit('main', 0xFF, 0x14, 0x24)             # call dword [esp]
    a.emit('main', 0x96)                         # xchg eax, esi
    a.label('scan', 'main')
    a.emit('main', 0xAC)                         # lodsb
    a.emit('main', 0x3C, 0x20)                   # cmp al, ' '
    a.j8('main', 0x74, 'got')
    a.emit('main', 0x84, 0xC0)                   # test al, al
    a.j8('main', 0x75, 'scan')
    a.emit('main', 0x4E)                         # dec esi: no arg -> stop at the NUL
    a.label('got', 'main')
    a.j32('main', 'h1start')
    a.label('f1', 'main')
    a.emit('main', 0x31, 0xDB)
    a.j8('main', 0xEB, 'found')
    a.label('f2', 'main')
    a.emit('main', 0x6A, 0x04)
    a.emit('main', 0x5B)
    a.j8('main', 0xEB, 'found')
    a.label('found', 'main')
    a.emit('main', 0x0F, 0xB7, 0x07)
    a.emit('main', 0x8B, 0x04, 0x82)
    a.emit('main', 0x03, 0xC6)
    a.emit('main', 0x89, 0x04, 0x1C)
    a.j8('main', 0xEB, 'adv')

    a.label('h1start', 'h1')
    a.emit('h1', 0x89, 0xF7)                     # mov edi, esi
    a.label('slen', 'h1')
    a.emit('h1', 0xAC)                           # lodsb
    a.emit('h1', 0x84, 0xC0)                     # test al, al
    a.j8('h1', 0x75, 'slen')
    a.j8('h1', 0xEB, 'h2start')

    a.label('h2start', 'h2')
    a.emit('h2', 0x29, 0xFE)                     # sub esi, edi
    a.emit('h2', 0x4E)                           # dec esi
    a.emit('h2', 0x6A, 0x00)
    a.emit('h2', 0x6A, 0x00)
    a.emit('h2', 0x56)                           # push esi
    a.emit('h2', 0x57)                           # push edi
    a.j8('h2', 0xEB, 'h3start')

    a.label('h3start', 'h3')
    a.emit('h3', 0x6A, 0xF5)
    a.emit('h3', 0xFF, 0x54, 0x24, 0x18)         # call [esp+0x18] WriteFile
    a.j8('h3', 0xEB, 'h4start')

    a.label('h4start', 'h4')
    a.emit('h4', 0x83, 0xC4, 0x10)
    a.emit('h4', 0x31, 0xC0)
    a.emit('h4', 0xC3)
    return pe_file(R, a.finalize(), 0x7C), a.finalize()


# --------------------------------------------------------------------------
# target 3: echo-stdin contiguous -- filter, 302 B (over the 268 budget)
# --------------------------------------------------------------------------
def build_echo_stdin():
    R = {'main': (0x7C, 400)}
    a = Asm(R)
    preamble(a, 'main')
    scan_head(a, 'main', H_READFILE, H_WRITEFILE)
    scan_adv(a, 'main')
    a.label('done', 'main')
    a.emit('main', 0x6A, 0x00)
    a.emit('main', 0x8D, 0x44, 0x24, 0x10)       # lea eax,[esp+0x10] = &n
    a.emit('main', 0x50)
    a.emit('main', 0x68, 0xFF, 0x07, 0, 0)       # push 0x7FF
    a.emit('main', 0x68, *struct.pack('<I', BUF))
    a.emit('main', 0x6A, 0xF6)                   # push -10 STD_INPUT_HANDLE
    a.emit('main', 0xFF, 0x54, 0x24, 0x14)       # call [esp+0x14] ReadFile
    a.emit('main', 0x6A, 0x00)
    a.emit('main', 0x6A, 0x00)
    a.emit('main', 0xFF, 0x74, 0x24, 0x14)       # push dword [esp+0x14] = n
    a.emit('main', 0x68, *struct.pack('<I', BUF))
    a.emit('main', 0x6A, 0xF5)
    a.emit('main', 0xFF, 0x54, 0x24, 0x18)       # call [esp+0x18] WriteFile
    a.emit('main', 0x83, 0xC4, 0x10)
    a.emit('main', 0x31, 0xC0)
    a.emit('main', 0xC3)
    scan_blocks(a, 'main')
    reg = a.finalize()
    return pe_file(R, reg, 0x7C), reg


# --------------------------------------------------------------------------
# target 4: echo-fold -- same code as target 3, tail folded into holes, 268 B
# --------------------------------------------------------------------------
def build_echo_fold():
    R = {'h1': (0x00C, 12), 'h2': (0x020, 12), 'h3': (0x030, 8),
         'h4': (0x044, 8), 'h5': (0x050, 4), 'main': (0x07C, 144)}
    a = Asm(R)
    # tail goes FIRST in main so h5 can reach it with a rel8 jump
    a.label('tail', 'main')
    a.emit('main', 0xFF, 0x54, 0x24, 0x18)       # call [esp+0x18] WriteFile
    a.emit('main', 0x83, 0xC4, 0x10)
    a.emit('main', 0x31, 0xC0)
    a.emit('main', 0xC3)

    preamble(a, 'main')
    scan_head(a, 'main', H_READFILE, H_WRITEFILE)
    scan_adv(a, 'main')
    a.label('done', 'main')
    a.emit('main', 0xBF, *struct.pack('<I', BUF))  # mov edi, BUF
    a.j32('main', 'h1start')
    scan_blocks(a, 'main')

    a.label('h1start', 'h1')
    a.emit('h1', 0x6A, 0x00)
    a.emit('h1', 0x8D, 0x44, 0x24, 0x10)
    a.emit('h1', 0x50)
    a.emit('h1', 0x6A, 0x7F)
    a.j8('h1', 0xEB, 'h2start')
    a.label('h2start', 'h2')
    a.emit('h2', 0x57)
    a.emit('h2', 0x6A, 0xF6)
    a.emit('h2', 0xFF, 0x54, 0x24, 0x14)
    a.j8('h2', 0xEB, 'h3start')
    a.label('h3start', 'h3')
    a.emit('h3', 0x6A, 0x00)
    a.emit('h3', 0x6A, 0x00)
    a.j8('h3', 0xEB, 'h4start')
    a.label('h4start', 'h4')
    a.emit('h4', 0xFF, 0x74, 0x24, 0x14)
    a.emit('h4', 0x57)
    a.j8('h4', 0xEB, 'h5start')
    a.label('h5start', 'h5')
    a.emit('h5', 0x6A, 0xF5)
    a.j8('h5', 0xEB, 'tail')
    reg = a.finalize()
    return pe_file(R, reg, 0x86), reg


TARGETS = [
    ('hello-268.exe', build_hello),
    ('hello-echo-arg.exe', build_echo_arg),
    ('hello-echo-fold.exe', build_echo_fold),
    ('hello-echo-stdin.exe', build_echo_stdin),
]


if __name__ == '__main__':
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'build')
    out = os.path.abspath(out)
    os.makedirs(out, exist_ok=True)
    for name, fn in TARGETS:
        data, reg = fn()
        path = os.path.join(out, name)
        open(path, 'wb').write(data)
        used = ', '.join(f'{k}={len(v)}' for k, v in reg.items())
        print(f'{name:22s} {len(data):4d} B   {used}')
