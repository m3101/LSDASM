"""
    LSDASM - An assembler for the UnB ENE 111821 course processor
    Copyright (C) 2021 Amélia Oliveira Freitas da Silva

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import re
from collections.abc import Iterable
import sys
import pdb

#Custom compilation errors
class Error(Exception):
    message = "Generic error"
    def __str__(self):
        return self.message
class LexicalError(Error):
    """
    Exception raised for errors on the lexical level of compilation.
    """
    def __init__(self, line, lineNumber,path):
        self.message = f">>{lineNumber}\t{line}\n\nLexical error:\tUnknown structure\nFile \"{path}\", line {lineNumber} is not an instruction, memory definition, label or section specifier\n"
class SyntacticError(Error):
    """
    Exception raised for errors on the syntactic level of compilation.
    """
    def __init__(self, lineNumber,msg,path):
        self.message = f"Syntax error:\nFile \"{path}\", line {lineNumber} - {msg}\n"
class SemanticError(Error):
    """
    Exception raised for errors on the semantic level of compilation.
    """
    def __init__(self, lineNumber,msg,path):
        self.message = f"Semantic error:\nFile \"{path}\", line {lineNumber} - {msg}\n"

#Instruction set
"""
Defined as
instruction:{
    r2r - opcode for register operation (r0,r1)
    a2r - opcode for absolute operation (r0,10)
    m2r - opcode for memory addressed operation (r0,$1000)
}
"""
instructions = {
    'add':{
        'r2r':0,
        'a2r':0
    },
    'sub':{
        'r2r':1,
        'a2r':1
    },
    'and':{
        'r2r':4,
        'a2r':4
    },
    'or':{
        'r2r':5,
        'a2r':5
    },
    'xor':{
        'r2r':6,
        'a2r':6
    },
    'mov':{
        'r2r':8,
        'a2r':8,
        'm2r':9
    }
}

#Scanning
rf"""
Here we build the regEx pattern we'll use
to both decompose lines and check for valid lines.

Structure: The expression is divided in 5 sections:
* (?:section +\.([a-z0-9]+))(?:;.*)?|
    * Matches a section definition (e.g. section .data)
* (?:([a-z0-9]+) +(d[wb]) (.+))(?:;.*)?|
    * Matches a memory definition (.data section lines, e.g. msg dw 'HELLO WORLD')
* (?:([a-z]{3,}) +([a-z0-9]+) *, *([a-z0-9]+))(?:;.*)?|
    * Matches an instruction ("instruction destination,origin", e.g. mov R0,10)
* ([a-z0-9_]+:)(?:;.*)?|
    * Matches a label
* (?:;(.*))
    * Matches a comment

Groups:
1 - section name
2 - memory definition name
3 - memory definition type
4 - memory definition content
5 - instruction name
6 - instruction destination
7 - instruction origin
8 - Label
9 - A semicolon if it's a comment (for easier parsing)

If a non-empty line doesn't match any of those, it's invalid.
"""
validline = re.compile(r"(?:section +\.([a-z0-9]+))(?:;.*)?|(?:([a-z0-9]+) +(d[wb]) (.+))(?:;.*)?|(?:([a-z]{3,}) +([a-z0-9]+) *, *([a-z0-9\[\]]+))(?:;.*)?|([a-z0-9_]+:)(?:;.*)?|(?:(;).*)")

def text_to_structured_data(lines:Iterable,path:str)->list:
    """
    Parses a string iterable object into a structured list with items on the following format:
    (lineNumber,regex Match object)
    """
    ret = []
    line_n = 1
    for line in lines:
        line = line.strip()
        if line:
            m = re.match(validline,line)
            if m is None:
                raise LexicalError(line,line_n,path)
            ret.append((line_n,m))
        line_n+=1
    return ret

#Separating sections

def structured_data_to_sections(sd:list,path:str)->list:
    """
    Separates a parsed structured list into two processable sections
    """
    sections = {
        'data':[2,3,4],
        'text':[5,6,7,8]
    }
    expected = {
        'data':"memory declarations (<name> db/dw <data>)",
        'text':"instructions or labels"
    }
    ret = {n:[] for n in sections}
    cs = None
    for item in sd:
        groups = item[1]
        if cs == None and groups[1] is None and groups[9] is None:
            raise SyntacticError(item[0],"Statement outside data/text section",path)
        if groups[1] is None:
            statement = [groups[i] for i in sections[cs]]
            if all([g is None for g in statement]):
                if not (groups[9] and all([groups[i] is None for i in range(1,9)])):
                    raise SyntacticError(item[0],f"Misplaced/Malformed statement on {cs} section. Expecting {expected[cs]}",path)
                else:
                    #;Comment
                    continue
            ret[cs].append([item[0]]+statement)
        else:
            if not groups[1] in sections:
                raise SyntacticError(item[0],"Unknown section",path)
            cs = groups[1]
    return ret

#Data section compilation

#Item separation regEx
memoryitem = re.compile(r"""[\"'][^"]+?[\"']|h\d+|\d+""")
def data_section(statement_list:list,path:str)->tuple:
    """
    Generates a data section from a statement list and returns
    a tuple (section:bytes,addresses:dict)
    """
    bytelist = list(b'DATA')
    addresses = dict()
    addr = 4
    for statement in statement_list:
        if statement[1] in addresses:
            raise SemanticError(statement[0],f"Ambiguous declaration - Data label \"{statement[1]}\" is already defined on a previous line",path)
        b = []
        for component in re.findall(memoryitem,statement[3]):
            if component[0]=="'" or component[0]=='"':
                b = b+[ord(c) for c in list(component[1:-1].replace("\\n","\n").replace("\\t","\t"))]
            elif component[0]=="h":
                try:
                    b.append(int(component[1:],16))
                except:
                    raise SyntacticError(statement[0],f"Number \"{component[1:]}\" is not a valid hexadecimal",path)
            else:
                try:
                    b.append(int(component))
                except:
                    raise SyntacticError(statement[0],f"Number \"{component}\" is not a valid decimal",path)
        addresses[statement[1]] = addr
        if statement[2]=='dw':
            for c in b:
                bytelist.append(0)
                bytelist.append(c)
            addr+=len(b)*2
        else:
            if len(b)%2==1:
                print(f"Warning: \"{path}\", line {statement[0]} - Binary definition is misaligned with word size. Padding with zeros")
                b=b+[0]
            bytelist=bytelist+b
            addr+=len(b)
    return (bytes(bytelist),addresses)

#Text section compilation
#Instruction Structure: OSCD-AAAA
# S=Source register
# D=Destination register
# O=Opcode
# C=Use next word?
# A=Data
indexedMemory = re.compile(r'([a-z0-9]+)((?:\[\d+\])?)')
def text_section_intermediate(statement_list:list,path:str,data_addrs:dict)->tuple:
    """
    Generates a text section intermediate compilable list from a statement list and returns
    a tuple (compilable:list,addresses:dict,size:int).
    Each item in the list has the format ([byte 0, byte 1, byte 2, byte 3,...])
    If one of the bytes is a string, it will be replaced by the corresponding address
    """
    ret = []
    addresses = []
    addr = 0
    for statement in statement_list:
        b = []
        m = re.match(indexedMemory,statement[3])
        name,index = [m[i] for i in [1,2]]
        #If not a label
        if statement[4] is None:
            if not statement[1] in instructions:
                raise SyntacticError(statement[0],f"Unknown instruction \"{statement[1]}\"",path)
            if statement[2][0]!='r':
                raise SyntacticError(statement[0],f"Instruction destination has to be a register (found \"{statement[2]}\")",path)
            #If register-addressing on the origin
            if statement[3][0]=='r':
                if not 'r2r' in instructions[statement[1]]:
                    raise SyntacticError(statement[0],f"Instruction doesn't support register addressing",path)
                b=b+[(instructions[statement[1]]['r2r']<<4)+int(statement[3][1:]),int(statement[2][1:])]
                addr+=2
            #If origin is a hex value
            elif statement[3][0]=='h':
                if not 'a2r' in instructions[statement[1]]:
                    raise SyntacticError(statement[0],f"Instruction doesn't support absolute value operations",path)
                v=int(statement[3][1:],16)
                b=b+[(instructions[statement[1]]['a2r']<<4),(1<<4)+int(statement[2][1:]),(v>>8),v&0xff]
                addr+=4
            #If origin is a data label
            elif name in data_addrs:
                if not 'm2r' in instructions[statement[1]]:
                    raise SyntacticError(statement[0],f"Instruction doesn't support memory addressing",path)
                print(f"Warning: \"{path}\", line {statement[0]} - Memory addressing is still unsupported. Prototype instruction.")
                b=b+[(instructions[statement[1]]['m2r']<<4),(1<<4)+int(statement[2][1:]),statement[3]]
                addr+=4
            #Test if it's a decimal
            else:
                if not 'a2r' in instructions[statement[1]]:
                    raise SyntacticError(statement[0],f"Instruction doesn't support absolute value operations",path)
                try:
                    v=int(statement[3])
                    b=b+[(instructions[statement[1]]['a2r']<<4),(1<<4)+int(statement[2][1:]),(v>>8),v&0xff]
                    addr+=4
                except:
                    raise SyntacticError(statement[0],f"Malformed/unknown origin \"{statement[3]}\"",path)
        else:
            if statement[4] in addresses:
                raise SemanticError(statement[0],f"Ambiguous declaration: label \"{statement[4]}\" defined in a previous line",path)
            if statement[4] in data_addrs:
                raise SemanticError(statement[0],f"Ambiguous declaration: label \"{statement[4]}\" is already defined in the data section",path)
            addresses[statement[4]]=addr
        if b:
            ret = ret+b
    return (ret,addresses,addr)

def text_section_final(statement_list:list,text_size:int,text_addrs:list,data_addrs:list):
    ret = []
    for statement in statement_list:
        if type(statement)==str:
            m = re.match(indexedMemory,statement)
            name,index = [m[i] for i in [1,2]]
            if name in text_addrs:
                a=text_addrs[name]
                ret.append((a>>8)&0xff)
                ret.append((a)&0xff)
            if name in data_addrs:
                a=data_addrs[name]+text_size+(int(index[1:-1])*2 if index else 0)
                ret.append((a>>8)&0xff)
                ret.append((a)&0xff)
        else:
            ret.append(statement)
    return bytes(ret)

#If we're being run as the main module (as opposed to being used as a separate module)
if __name__ == "__main__":
    if len(sys.argv)<2:
        print("Usage: python LSDASM.py <source file> [-v]")
        exit(0)
    with open(sys.argv[1],'r') as f:
        try:
            #Structure the input
            structured = text_to_structured_data(f,sys.argv[1])
            #Separate the sections
            sect = structured_data_to_sections(structured,sys.argv[1])
            #Compile the data section
            ds,addrs = data_section(sect['data'],sys.argv[1])
            #Do the intermediate compilation on the text section
            i_ts,taddrs,ts_size = text_section_intermediate(sect['text'],sys.argv[1],addrs)
            #Calculate the data addresses
            ts = text_section_final(i_ts,ts_size,taddrs,addrs)
            #Put the sections together
            binary = b''.join([ts,ds])
        except (LexicalError,SyntacticError) as e:
            print(e)
            exit(1)
        fname = "a.out" if len(sys.argv)<3 else sys.argv[2]
        with open(fname,'wb') as of:
            of.write(binary)
            print("\nResulting addresses:")
            print(".text\t0x0")
            for a in taddrs:
                print(f"\t{hex(taddrs[a])}\t{a}")
            print(f".data\t{hex(ts_size)}")
            for a in addrs:
                print(f"\t{hex(addrs[a]+ts_size)}\t{a}")
            print("\n\nVerilog-pasteable array:")
            print(f"reg [7:0] prog [{len(binary)-1}:0];")
            print(f"assign {{{','.join([f'prog[{i}]' for i in range(len(binary))])}}} = ", end='')
            data = ','.join([f'8\'d{b}' for b in binary])
            print(f"{{{data}}};")