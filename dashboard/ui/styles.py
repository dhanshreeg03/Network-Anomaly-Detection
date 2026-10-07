def get_custom_css():
    return """
    <style>
        /* Editorial Typography & Layout with Elevated Panels */
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600&display=swap');
        
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
            color: #1E293B;
            background-color: #F5F7FA;
        }
        
        h1, h2, h3, h4, h5, .hero-heading, .section-heading {
            font-family: 'Space Grotesk', sans-serif !important;
            color: #0F172A !important;
            font-weight: 700 !important;
            letter-spacing: -0.03em !important;
        }
        
        /* Navigation Bar */
        .cg-nav-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            margin-bottom: 30px;
            border-bottom: 1px solid #E2E8F0;
        }
        
        .cg-nav-brand {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            letter-spacing: -0.05em;
            color: #0F172A;
        }
        
        /* Typography Elements */
        .hero-heading {
            font-size: 5rem;
            line-height: 1.1;
            margin: 0 0 15px 0;
            text-transform: uppercase;
        }
        
        .hero-subtitle {
            font-size: 1.25rem;
            font-weight: 400;
            color: #475569;
            max-width: 650px;
            margin-bottom: 40px;
            line-height: 1.6;
        }
        
        .section-heading {
            font-size: 2.5rem;
            line-height: 1.2;
            margin: 0 0 10px 0;
            text-transform: uppercase;
        }
        
        .eyebrow {
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: #64748B;
            margin-bottom: 8px;
            display: block;
        }
        
        /* Elevated Panels */
        .cg-panel {
            background-color: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.02), 0 2px 4px -1px rgba(0, 0, 0, 0.02);
            margin-bottom: 25px;
            transition: box-shadow 0.2s;
        }
        
        .cg-panel:hover {
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.04), 0 4px 6px -2px rgba(0, 0, 0, 0.02);
        }
        
        .result-panel {
            border-radius: 12px;
            padding: 40px;
            margin-top: 30px;
            margin-bottom: 30px;
            border: 1px solid #E2E8F0;
        }
        
        .result-panel-attack {
            background-color: #FEF2F2;
            border-top: 4px solid #EF4444;
        }
        
        .result-panel-normal {
            background-color: #F0FDF4;
            border-top: 4px solid #22C55E;
        }
        
        /* Editoral Metrics */
        .metric-large {
            padding: 20px 0;
        }
        
        .metric-large .value {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 3rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 8px;
            color: #0F172A;
        }
        
        .metric-large .label {
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #64748B;
        }
        
        /* Badges */
        .attack-badge {
            display: inline-block;
            padding: 6px 14px;
            font-family: 'Inter', sans-serif;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-radius: 6px;
        }
        
        .badge-critical, .badge-high { 
            color: #B91C1C; 
            background-color: #FEE2E2; 
            border: 1px solid #FCA5A5; 
        }
        .badge-medium { 
            color: #C2410C; 
            background-color: #FFEDD5; 
            border: 1px solid #FDBA74; 
        }
        .badge-low { 
            color: #1D4ED8; 
            background-color: #DBEAFE; 
            border: 1px solid #93C5FD; 
        }
        .badge-normal { 
            color: #15803D; 
            background-color: #DCFCE7; 
            border: 1px solid #86EFAC; 
        }
        
        /* Data Display Lists */
        .data-list {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px 40px;
        }
        
        .data-list-item {
            display: flex;
            justify-content: space-between;
            padding-bottom: 8px;
            border-bottom: 1px solid #E2E8F0;
        }
        
        .data-list-label {
            color: #64748B;
            font-weight: 500;
            font-size: 0.95rem;
        }
        
        .data-list-value {
            font-weight: 600;
            color: #0F172A;
            font-size: 0.95rem;
        }
        
        /* Workflow Cards (01, 02) */
        .workflow-card {
            background-color: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-top: 4px solid #2563EB;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.02);
            transition: all 0.2s ease;
        }
        
        .workflow-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.05);
        }
        
        .workflow-num {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.25rem;
            font-weight: 700;
            color: #94A3B8;
            margin-bottom: 10px;
        }
        
        /* Streamlit Overrides */
        .stButton>button {
            border-radius: 8px;
            font-weight: 600;
            letter-spacing: 0.02em;
            border: 1px solid #E2E8F0;
            background-color: #FFFFFF;
            color: #0F172A;
            padding: 10px 24px;
            box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            transition: all 0.2s;
        }
        
        .stButton>button[data-baseweb="button"]:hover {
            background-color: #F8FAFC;
            border-color: #CBD5E1;
            color: #0F172A !important;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }
        
        .stSelectbox label, .stNumberInput label {
            text-transform: uppercase;
            font-weight: 600 !important;
            font-size: 0.8rem !important;
            letter-spacing: 0.05em;
            color: #475569;
        }
        
        div[data-testid="stSidebar"] {
            display: none;
        }
        
        /* Upload Area */
        .upload-area {
            border: 2px dashed #CBD5E1;
            border-radius: 12px;
            padding: 60px 20px;
            text-align: center;
            background-color: #F8FAFC;
            margin-bottom: 30px;
            transition: background-color 0.2s;
        }
        
        .hero-bg {
            position: absolute;
            top: 0; left: 0; right: 0; height: 500px;
            background: linear-gradient(180deg, #F1F5F9 0%, rgba(241, 245, 249, 0) 100%);
            z-index: -1;
            pointer-events: none;
        }
    </style>
    """
