#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" CRCFix v2.19 by Kirlif' """
from os import path
from io import BytesIO
from sys import exit


def ifb(b):
    return int.from_bytes(b, "little")


class ZIPElement:
    def __init__(self, name):
        self.name = name
        self.cd_lmt_offset, self.lf_lmt_offset, self.lmt = None, None, None
        self.cd_lmd_offset, self.lf_lmd_offset, self.lmd = None, None, None
        self.cd_crc_offset, self.lf_crc_offset, self.crc = None, None, None

    def dos_date(self):
        date = ifb(self.lmd)
        d = f"{0x7bc + ((date >> 0x9) & 0x7f)}-"
        d += f"0{(date >> 0x5) & 0xf}-"[-3:]
        d += f"0{date & 0x1f}"[-2:]
        return d

    def dos_time(self):
        time = ifb(self.lmt)
        t = f"0{((time >> 0x11) & 0x1f)}:"[-3:]
        t += f"0{((time >> 0x5) & 0x3f)}:"[-3:]
        t += f"0{2*(time & 0x1f)}"[-2:]
        return t


class CRCFix:
    END_OF_CENTRAL_SIG = b"PK\x05\x06"
    CENTRAL_HEADER_SIG = b"PK\x01\x02"
    LOCAL_HEADER_SIG = b"PK\x03\x04"

    def __init__(self, src, tar, fix_crc, auto, timestamp, overwrite):
        self.src = src
        self.tar = tar
        self.fix_crc = fix_crc
        self.auto = auto
        self.timestamp = timestamp
        self.overwrite = overwrite
        self.fixed = list()
        self.last_dex_elem = None
        self.last_dex_n = 0
        self.src_elems = self.get_src_elems()
        self.tar_elems = self.get_elems(tar)

    def get_src_elems(self):
        elems_dict = {}
        for s in self.src:
            elems = self.get_elems(s)
            for k in iter(elems):
                if not k in elems_dict:
                    elems_dict[k] = elems[k]
        return elems_dict

    def get_elems(self, apk):
        elems = {}
        with open(apk, "rb") as g:
            f = BytesIO(g.read())
        f.seek(-22, 2)
        meocd, central_offset = f.tell(), None
        while f.tell() >= 0:
            if f.read(4) == self.END_OF_CENTRAL_SIG:
                f.seek(8, 1)
                size_of_cd = ifb(f.read(4))
                central_offset = ifb(f.read(4))
                break
            if meocd - f.tell() > 1 << 16:
                break
            f.seek(-5, 1)
        if central_offset is None:
            exit(f"\nEOCD not found!\n{path.basename(apk)} is damaged or not an APK.\n")
        f.seek(central_offset)
        while f.tell() < central_offset + size_of_cd:
            if not f.read(4) == self.CENTRAL_HEADER_SIG:
                exit("Central Header not found!\n")
            f.seek(8, 1)
            lmt_offset, cd_lmt = f.tell(), f.read(2)
            lmd_offset, cd_lmd = f.tell(), f.read(2)
            crc_offset, cd_crc = f.tell(), f.read(4)
            f.seek(8, 1)
            file_name_length = ifb(f.read(2))
            extra_field_length = ifb(f.read(2))
            file_comment_length = ifb(f.read(2))
            f.seek(8, 1)
            relative_offset_of_local_header = ifb(f.read(4))
            file_name = f.read(file_name_length).decode()
            zel = ZIPElement(file_name)
            zel.cd_lmt_offset, zel.lmt = lmt_offset, cd_lmt
            zel.cd_lmd_offset, zel.lmd = lmd_offset, cd_lmd
            zel.cd_crc_offset, zel.crc = crc_offset, cd_crc
            of = f.tell()
            f.seek(relative_offset_of_local_header)
            if not f.read(4) == self.LOCAL_HEADER_SIG:
                exit("Local Header not found!\n")
            f.seek(6, 1)
            zel.lf_lmt_offset, lf_lmt = f.tell(), f.read(2)
            zel.lf_lmd_offset, lf_lmd = f.tell(), f.read(2)
            zel.lf_crc_offset, lf_crc = f.tell(), f.read(4)
            f.seek(of)
            if not all([cd_lmt == lf_lmt, cd_lmd == lf_lmd, cd_crc == lf_crc]):
                exit("Headers don't match!\n")
            if file_name.startswith("classes") and file_name.endswith(".dex"):
                if apk is self.src[0]:
                    d = zel.name[7:-4]
                    n = 1 if not d else int(d)
                    if self.last_dex_elem is None or n > self.last_dex_n:
                        self.last_dex_elem = zel
                        self.last_dex_n = n
                elif apk is self.tar and not file_name in self.src_elems:
                    self.src_elems[file_name] = self.last_dex_elem
            elems[file_name] = zel
            f.seek(extra_field_length + file_comment_length, 1)
        return elems

    def print(self):
        if self.fixed:
            elems = sorted([elem for elem in self.fixed], key=lambda elem: elem.name)
            ml = max(len(elem.name) for elem in elems) + 4
            print(
                "{:{ml}}{:<12}{:<12}{:<23}".format(
                    "File Name", "CRC", "FIX", "Modified", ml=ml
                )
            )
            for e in elems:
                e_e = self.src_elems[e.name]
                print(
                    "{:{ml}}{:<12}{:<12}{:<23}".format(
                        e.name,
                        hex(ifb(e.crc))[2:],
                        hex(ifb(e_e.crc))[2:],
                        f"{e_e.dos_date()} {e_e.dos_time()}",
                        ml=ml,
                    )
                )
            print(
                f"\nInput:  {self.tar}\nOutput: {self.apk_crc}\n\nFixed CRCs: {len(elems)}\n"
            )
        else:
            print(f"Input:  {self.tar}\nOutput: {self.apk_crc}\n")

    def fix(self):
        root, ext = path.splitext(self.tar)
        self.apk_crc = f'{root}{"" if self.overwrite else "_crc"}{ext}'
        print("\n\u2728 CRCFix 2.19 by Kirlif' \u2728\n")
        with open(self.tar, "rb") as g:
            f = bytearray(g.read())
        with open(self.apk_crc, "wb") as g:
            for elem in self.tar_elems.values():
                try:
                    if self.timestamp:
                        lmt = self.src_elems[elem.name].lmt
                        f[elem.cd_lmt_offset : elem.cd_lmt_offset + 2] = lmt
                        f[elem.lf_lmt_offset : elem.lf_lmt_offset + 2] = lmt
                        lmd = self.src_elems[elem.name].lmd
                        f[elem.cd_lmd_offset : elem.cd_lmd_offset + 2] = lmd
                        f[elem.lf_lmd_offset : elem.lf_lmd_offset + 2] = lmd
                    crc = self.src_elems[elem.name].crc
                    if (
                        self.fix_crc
                        and not self.tar_elems[elem.name].crc == crc
                        and (
                            self.auto
                            or elem.name.startswith("classes")
                            and elem.name.endswith(".dex")
                        )
                    ):
                        self.fixed.append(elem)
                        f[elem.cd_crc_offset : elem.cd_crc_offset + 4] = crc
                        f[elem.lf_crc_offset : elem.lf_crc_offset + 4] = crc
                except KeyError:
                    pass  # ~ Worried about this?
            g.write(f)
        self.print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="""CRCFix restores files CRC and date/time of a modified APK""",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version="CRCFix v2.19")
    parser.add_argument(
        "source", nargs="+", help="APKs source paths (base first)", type=str
    )
    parser.add_argument("target", help="APK target path", type=str)
    parser.add_argument("-c", action="store_false", help="do not restore CRCs")
    parser.add_argument("-d", action="store_false", help="apply on dex files only")
    parser.add_argument("-t", action="store_false", help="do not restore date/time")
    parser.add_argument("-f", action="store_true", help="overwrite target")
    args = parser.parse_args()
    CRCFix(
        args.source, args.target, args.c, args.d, args.t, args.f
    ).fix() if args.c or args.d and args.t else parser.print_help()
