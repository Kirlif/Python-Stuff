#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
hbclabel injects branch label as comments into Hermes byte code disassemby produced by hbctool.
They are removed once re-assembled.

Ex:

Function<k>7654(3 params, 3 registers, 0 symbols):
	LoadParam           	Reg8:2, UInt8:1
	LoadConstNull       	Reg8:0
	JmpFalse            	Addr8:10, Reg8:2 |
;L_0                                          | <-----  BRANCH (;L_i)
	LoadParam           	Reg8:1, UInt8:2
	GetByVal            	Reg8:0, Reg8:1, Reg8:2
;L_0:                                         |  <------ LABEL (;L_i:)
	Ret                 	Reg8:0
EndFunction


hbclabel [File]

If no file is passed, « instruction.hasm » in current dir is proccessed by default.

Created by Kirlif'
'''

import re, shutil, sys

class hbclabel:
    def __init__(self, hasm):
        self.hasm = hasm
        self.hasm_tmp = hasm+'_lbl'
        self.func_list = list()

        shutil.copyfile(self.hasm, self.hasm_tmp)

        self.get_func()
        self.write_hasm()

    def get_func(self):
        print('- Reading hasm...')
        with open(self.hasm_tmp, 'r') as f:
            for m in re.finditer(re.compile('Function<.*?EndFunction\n', re.S), f.read()):
                self.func_list.append(m)

    def write_hasm(self):
        print('- Writing labels...')
        l = len(self.func_list)
        w, _ = shutil.get_terminal_size()
        with open(self.hasm_tmp, 'w') as g:
            for i, f in enumerate(self.func_list):
                f = f.group()+'\n'
                g.write(self.process_func(f)) if '\tAddr' in f else g.write(f)
                self.progress_bar(i+1, l, round(w*2/3))
        shutil.move(self.hasm_tmp, self.hasm)

    def process_func(self, f):
        f = f.splitlines(True)
        g, l, labs = f.copy(), 0, {}
        for i in range(len(g)):
            if '\tAddr' in g[i]:
                tar = int(g[i].split('\tAddr')[1].split(',')[0].split(':')[1].rstrip())
                try:
                    lpl = i+(self.w_label(tar, g[i:]) if tar > 0 else -(self.w_label(-tar, g[:i][::-1])+2))
                except:
                    self.exit(f'- Error in {g[0].split("(")[0]} !!!\n{i+1, g[i].strip()}')
                if not lpl in labs:
                    f[lpl+(2 if g[lpl+1].startswith('\t;') else 0)] += f';L_{l}:\n'
                    labs[lpl] = l
                    l += 1
                if f[i+1] == f';L_{labs[lpl]}\n':
                    self.exit('- Aborted, labels are already there!')
                f[i] = f[i].replace('\n',f'\n;L_{labs[lpl]}\n', 1)
        return ''.join(f)

    def w_label(self, tar, sub_f):
        ofs = 0
        for i in range(len(sub_f)):
            l = sub_f[i].strip()
            if l.startswith(';') or l == '':
                continue
            spl = l.split(', ')
            for j in range(len(spl)):
                k = 1 if j == 0 and not spl[j] in ['AsyncBreakCheck', 'CompleteGenerator', 'Debugger', 'DebuggerCheckBreak', 'StartGenerator', 'Unreachable'] else 0
                if '16:' in spl[j]:
                    ofs += 2+k
                elif '32:' in spl[j]:
                    ofs += 4+k
                elif '64:' in spl[j] or 'Double:' in spl[j]:
                    ofs += 8+k
                else:
                    ofs += 1+k
            if ofs == tar:
                return i

    def exit(self, m):
        from os import remove
        remove(self.hasm_tmp)
        print(m)
        sys.exit()

    def progress_bar(self, i, l, w):
        c = round(w*i/l)
        print('['+'#'*c+chr(0xb7)*(w-c)+']\r', end='')

if __name__ == "__main__":
    p = len(sys.argv)
    if p < 3:
        hasm_file = sys.argv[1] if p == 2 else 'instruction.hasm'
        print('\u2728 hbclabel by Kirlif\' \u2728')
        hbclabel(hasm_file)
        print('\nDone.')
