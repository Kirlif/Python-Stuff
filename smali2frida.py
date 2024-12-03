#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Smali2Frida class generates a list of frida snippet from smali files (snippets).

smali2frida.py [DIR] > script.js

If no directory (with smali folders) is passed the current one is used by default.

06-03-2022
Created by Kirlif'
modified by Th3-r3p4ck3r 
'''

from os import getcwd, path, scandir
import re

class Smali2Frida:
    class_pattern = re.compile(r'\.class.+?(\S+?;)', re.UNICODE)
    method_pattern = re.compile(r'\.method.+?(\S+?)\((\S*?)\)(\S+)', re.UNICODE)
    param_pattern = re.compile(r'(\[*L\S+?;|\[+\S|B|C|D|F|I|J|S|Z)', re.UNICODE)
    primitives = {"B": "byte", "C": "char", "D": "double", "F": "float", "I": "int", "J": "long", "S": "short", "Z": "boolean"}

    def __init__(self, _dir=getcwd()):
        self.root_dir = _dir
        self.snippets = []
        self.frida()

    def scan(self, root, rec=True):
        for entry in scandir(root):
            if entry.is_dir(follow_symlinks=False) and rec:
                yield from self.scan(entry.path)
            else:
                yield entry

    def smali_files(self):
        _files = []
        for folder in [entry.path for entry in self.scan(self.root_dir, False) if path.isdir(entry) and path.split(entry)[-1].startswith("smali")]:
            _files += [entry.path for entry in self.scan(folder, True) if path.split(entry)[-1].endswith(".smali")]
        return _files

    def smali_data(self):
        data = {}
        for sf in self.smali_files():
            with open(sf, 'r', encoding='utf-8', errors='surrogateescape') as _file:
                class_name = ''
                for line in _file:
                    if not class_name:
                        class_match = self.class_pattern.match(line)
                        if class_match:
                            class_name = class_match.group(1)[1:-1].replace('/', '.')
                            data[class_name] = []
                            continue
                    if class_name:
                        method_match = self.method_pattern.match(line)
                        if method_match:
                            method_name = method_match.group(1)
                            method_param, find_all = '', re.findall(self.param_pattern, method_match.group(2))
                            for p in find_all:
                                p = p[1:-1].replace('/', '.') if p.startswith('L') else p
                                p = self.primitives[p] if p in self.primitives else p
                                method_param += f'\'{p}\', '
                            data[class_name].append((method_name, method_param[:-2], len(find_all)))
        return {k: data[k] for k in sorted(data) if data[k]}

    def frida(self):
        classes = self.smali_data()
        l = len(str(len(classes)))
        for i, k in enumerate(classes):
            methods = classes[k]
            klass = f'C{(l * "0" + str(i))[-l:]}'
            snippet = f'Java.perform(function() {{\n    var {klass} = Java.use("{k}");\n'
            for method in methods:
                met = '$init' if method[0] == '<init>' else method[0]
                apa = ", ".join(f"var{j}" for j in range(method[2]))
                snippet += f'\n    {klass}.{met}.overload({method[1]}).implementation = function({apa})\n'
                snippet += f'    {{\n        var ret = this.{met}({apa});\n'
                
                # Check if there are no arguments
                if method[2] == 0:
                    snippet += f'        console.log("[{klass}.{method[0]}]", "no arg");\n'
                else:
                    # Print each argument on a new line
                    for j in range(method[2]):
                        snippet += f'        console.log("[{klass}.{method[0]}]", "arg{j}:", var{j});\n'
                
                snippet += f'        console.log("[{klass}.{method[0]}]", "returned: ", ret);\n'
                snippet += f'        console.log("----------------------------------------------------------------");\n'
                snippet += f'        return ret;\n    }};\n'
            snippet += ('})\n')
            self.snippets.append(snippet)

if __name__ == "__main__":
    from sys import argv
    _dir = argv[-1] if path.isdir(argv[-1]) else getcwd()
    [print(snippet) for snippet in Smali2Frida(_dir).snippets]