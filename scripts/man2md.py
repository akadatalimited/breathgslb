#!/usr/bin/env python3
import sys, re

def clean(line):
    # remove macro escapes
    line=line.replace('\fI','').replace('\fR','')
    line=line.replace('fI','').replace('fR','')
    line=line.replace('\\-','-')
    line=line.replace('\\', '')
    return line

def man_to_md(path):
    out=[]
    with open(path,'r',encoding='utf-8') as f:
        lines=f.readlines()
    i=0
    while i < len(lines):
        line=lines[i].rstrip('\n')
        if line.startswith('.TH'):
            i+=1; continue
        if line.startswith('.SH '):
            out.append('# '+clean(line[4:]))
            i+=1; continue
        if line.startswith('.TP'):
            i+=1
            term=clean(lines[i].strip())
            term=re.sub(r'^\.B\s+','',term)
            term=re.sub(r'^\.BR\s+','',term)
            term=re.sub(r'^\.I\s+','',term)
            term=re.sub(r'^\.IR\s+','',term)
            out.append('## '+term)
            i+=1
            continue
        if line.startswith('.B '):
            out.append('**'+clean(line[3:].strip())+'**')
            i+=1; continue
        if line.startswith('.I '):
            out.append('*'+clean(line[3:].strip())+'*')
            i+=1; continue
        if line.startswith('.BR ') or line.startswith('.RB '):
            txt=clean(line[4:])
            txt=txt.replace('"','')
            out.append(txt)
            i+=1; continue
        if line.startswith('.P') or line.startswith('.PP'):
            out.append('')
            i+=1; continue
        if line.startswith('."'):
            i+=1; continue
        if line.startswith('.'):  # unhandled macro
            i+=1; continue
        out.append(clean(line))
        i+=1
    return '\n'.join(out)

if __name__=='__main__':
    if len(sys.argv)!=3:
        print('usage: man2md.py input.man output.md')
        sys.exit(1)
    md=man_to_md(sys.argv[1])
    with open(sys.argv[2],'w',encoding='utf-8') as f:
        f.write(md)
