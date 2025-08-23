#!/usr/bin/env python3
import sys, re

def md_lines(md_path):
    lines=[]
    with open(md_path, 'r', encoding='utf-8') as f:
        for ln in f:
            ln=ln.rstrip('\n')
            ln=re.sub(r'^#+\s*', '', ln)
            ln=ln.replace('\t', '    ')
            lines.append(ln)
    return lines

def paginate(lines, start_y=760, line_h=14, bottom=40):
    pages=[]
    y=start_y
    page=[]
    for ln in lines:
        if y < bottom:
            pages.append(page)
            page=[]
            y=start_y
        if ln=="":
            y -= line_h
            continue
        page.append((ln, y))
        y -= line_h
    pages.append(page)
    return pages

def escape_text(s):
    s = s.encode('ascii', 'replace').decode('ascii')
    return s.replace('(', '\\(').replace(')', '\\)').replace('\\', '\\\\')


def build_pdf(pages, out_path):
    objs=[]
    # catalog and pages placeholders
    objs.append('1 0 obj<</Type /Catalog /Pages 2 0 R>>endobj\n')
    kids=[]
    for i in range(len(pages)):
        kids.append(f"{3 + 2*i} 0 R")
    objs.append(f"2 0 obj<</Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)}>>endobj\n")
    # page and content objects
    for i, page in enumerate(pages):
        page_obj = 3 + 2*i
        content_obj = 4 + 2*i
        stream_lines=['BT /F1 12 Tf']
        last_y=None
        for text,y in page:
            if last_y is None:
                stream_lines.append(f"72 {y} Td ({escape_text(text)}) Tj")
            else:
                dy = y - last_y
                stream_lines.append(f"0 {dy} Td ({escape_text(text)}) Tj")
            last_y = y
        stream_lines.append('ET')
        stream='\n'.join(stream_lines)
        objs.append(f"{page_obj} 0 obj<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {content_obj} 0 R /Resources<</Font<</F1 {3 + 2*len(pages)} 0 R>>>>>>endobj\n")
        objs.append(f"{content_obj} 0 obj<</Length {len(stream.encode('utf-8'))}>>stream\n{stream}\nendstream endobj\n")
    # font object
    font_obj = 3 + 2*len(pages)
    objs.append(f"{font_obj} 0 obj<</Type /Font /Subtype /Type1 /BaseFont /Helvetica>>endobj\n")
    # assemble pdf
    header='%PDF-1.4\n'
    xref_positions=[0]
    pdf=header
    for obj in objs:
        xref_positions.append(len(pdf.encode('latin-1')))
        pdf+=obj
    xref_start=len(pdf.encode('latin-1'))
    pdf+=f"xref\n0 {len(xref_positions)}\n"
    for pos in xref_positions:
        pdf+=f"{pos:010} 00000 n \n" if pos!=0 else '0000000000 65535 f \n'
    pdf+=f"trailer<</Root 1 0 R /Size {len(xref_positions)}>>\nstartxref\n{xref_start}\n%%EOF"
    with open(out_path, 'wb') as f:
        f.write(pdf.encode('latin-1'))

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('usage: md2pdf.py input.md output.pdf')
        sys.exit(1)
    lines = md_lines(sys.argv[1])
    pages = paginate(lines)
    build_pdf(pages, sys.argv[2])
