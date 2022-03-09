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
;L0                                          | <-----  BRANCH (;Li)
	LoadParam           	Reg8:1, UInt8:2
	GetByVal            	Reg8:0, Reg8:1, Reg8:2
;L0:                                         |  <------ LABEL (;Li:) 
	Ret                 	Reg8:0
EndFunction


hbclabel [File]

If no file is passed, « instruction.hasm » in current dir is proccessed by default.

Created by Kirlif'
'''

class hbclabel:
    def __init__(self, in_file):
        self.in_file, func_list = in_file, []
        with open(in_file, 'r') as f:
            hasm = f.readlines()
        for i in range(len(hasm)):
            line = hasm[i]
            if line.startswith('Function<'):
                start_func = i
            if line == 'EndFunction\n':
                func_list.append((start_func, i+1))
        with open(in_file, 'w') as g:
            for f in func_list:
                func = hasm[f[0]:f[1]]
                j_func = ''.join(func)
                g.write(self.process_func(func)+'\n') if '\tAddr' in j_func else g.write(j_func+'\n')

    def process_func(self, f):
        g, l, labs = f.copy(), 0, {}
        for i in range(len(g)):
            if '\tAddr' in g[i]:
                tar = int(g[i].split('\tAddr')[1].split(',')[0].split(':')[1].rstrip())
                try:
                    lpl = i+(self.w_label(tar, g[i:]) if tar > 0 else -(self.w_label(-tar, g[:i][::-1])+2))
                except:
                    from os import remove
                    remove(self.in_file)
                    sys.exit(f'Error in {g[0].split("(")[0]} !!!\n{i+1, g[i].strip()}')
                if not lpl in labs:
                    f[lpl+(2 if g[lpl+1].startswith('\t;') else 0)] += f';L{l}:\n'
                    labs[lpl] = l
                    l += 1
                f[i] = f[i].replace('\n',f'\n;L{labs[lpl]}\n', 1)
        return ''.join(f)

    def w_label(self, tar, sub_f):
        ofs = 0
        for i in range(len(sub_f)):
            l = sub_f[i].strip()
            if l.startswith(';') or l == '':
                continue
            spl = l.split(', ')
            for j in range(len(spl)):
                k = 1 if j == 0 else 0
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


if __name__ == "__main__":
    import shutil, sys
    p = len(sys.argv)
    if p > 2:
        sys.exit()
    hasm_file = sys.argv[1] if p == 2 else 'instruction.hasm'
    print('\u2728 hbclabel by Kirlif\' \u2728')
    shutil.copyfile(hasm_file, hasm_file+'_lbl')
    hbclabel(hasm_file+'_lbl')
    shutil.move(hasm_file+'_lbl', hasm_file)
    print('Done.')
