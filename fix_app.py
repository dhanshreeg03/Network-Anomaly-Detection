import re

with open('dashboard/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "st.markdown('<div class=\"cg-panel\">', unsafe_allow_html=True)" in line:
        continue
    if "st.markdown('</div>', unsafe_allow_html=True)" in line:
        continue
    new_lines.append(line)

with open('dashboard/app.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("Done removing broken wrappers.")
