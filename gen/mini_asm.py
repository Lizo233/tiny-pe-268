"""Region-aware x86 assembler for building PE files byte by byte.

Why not use fasm/nasm: every byte of a 268-byte PE matters, and the code has
to be *folded into the PE header fields*, which no normal assembler can
express.  Here a "region" is an arbitrary (virtual address, size) window, so
one logical program can be emitted as several fragments living in different
header fields.

Addresses are absolute VAs (ImageBase + file offset, valid because the image
has no sections).  Every jump is resolved from the absolute target and range
checked, so a layout mistake fails loudly instead of producing a broken exe.
"""


class Asm:
    def __init__(self, regions):
        """regions: {name: (va, max_size)}"""
        self.regions = regions
        self.code = {r: bytearray() for r in regions}
        self.labels = {}
        self.fix = []           # (region, pos, kind, target_label)

    # ---- emitting ----
    def emit(self, region, *bs):
        self.code[region] += bytes(bs)

    def label(self, name, region):
        self.labels[name] = self.regions[region][0] + len(self.code[region])

    def j8(self, region, op, target):
        """short jump/jcc: 2 bytes total"""
        self.emit(region, op, 0)
        self.fix.append((region, len(self.code[region]) - 1, 'rel8', target))

    def j32(self, region, target):
        """near jmp: E9 + rel32, 5 bytes"""
        self.emit(region, 0xE9, 0, 0, 0, 0)
        self.fix.append((region, len(self.code[region]) - 4, 'rel32', target))

    # ---- resolution ----
    def finalize(self):
        for region, pos, kind, target in self.fix:
            assert target in self.labels, f'undefined label {target}'
            here = self.regions[region][0] + pos + (1 if kind == 'rel8' else 4)
            disp = self.labels[target] - here
            if kind == 'rel8':
                assert -128 <= disp <= 127, (
                    f'{region}: jump to {target} out of rel8 range '
                    f'({disp}); move the fragment or use j32')
                self.code[region][pos] = disp & 0xFF
            else:
                import struct
                self.code[region][pos:pos + 4] = struct.pack('<i', disp)
        for r, (_, size) in self.regions.items():
            assert len(self.code[r]) <= size, (
                f'{r}: {len(self.code[r])} bytes > {size} available')
        return {r: bytes(v) for r, v in self.code.items()}
