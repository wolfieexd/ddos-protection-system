import re

with open('web-app/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# find start and end of DASHBOARD_HTML
start_marker = "DASHBOARD_HTML = '''<!DOCTYPE html>"
start_idx = content.find(start_marker)

# find the next </html>''' after start_idx
end_idx = content.find("</html>'''", start_idx)

if start_idx != -1 and end_idx != -1:
    end_idx += len("</html>'''")
    
    with open('patch_dashboard.py', 'r', encoding='utf-8') as f:
        patch_script = f.read()
    
    # Extract new_html from patch_dashboard.py
    # We can just extract everything between new_html = """<!DOCTYPE html> and """\n\nstart_marker
    import ast
    # let's just use regex to find new_html
    match = re.search(r'new_html\s*=\s*\"\"\"(.*?)\"\"\"', patch_script, re.DOTALL)
    if match:
        new_html = match.group(1)
        
        new_content = content[:start_idx] + "DASHBOARD_HTML = '''" + new_html + "'''" + content[end_idx:]
        with open('web-app/app.py', 'w', encoding='utf-8') as f:
            f.write(new_content)
        print("Successfully patched DASHBOARD_HTML")
    else:
        print("Failed to extract new_html")
else:
    print("Failed to find boundaries", start_idx, end_idx)
