import streamlit as st

def render_metric_large(label, value):
    """Renders a large editorial metric inside a panel."""
    st.markdown(f"""
        <div class="cg-panel" style="padding: 20px 30px; text-align: center;">
            <div class="metric-large" style="padding: 0;">
                <div class="value">{value}</div>
                <div class="label">{label}</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

def render_attack_badge(text, severity="normal"):
    """Returns HTML for an editorial badge."""
    css_class = f"attack-badge badge-{severity.lower()}"
    return f'<span class="{css_class}">{text}</span>'

def render_top_nav(active_page):
    """Renders the top navigation bar."""
    st.markdown(f"""
        <div class="cg-nav-container">
            <div class="cg-nav-brand">CYBERGUARD</div>
        </div>
    """, unsafe_allow_html=True)

def render_data_list(data_dict):
    """Renders a clean two-column key/value list inside a panel."""
    html = '<div class="cg-panel">\n<div class="data-list">\n'
    for label, val in data_dict.items():
        html += f'<div class="data-list-item">\n<div class="data-list-label">{label}</div>\n<div class="data-list-value">{val}</div>\n</div>\n'
    html += '</div>\n</div>'
    return html
