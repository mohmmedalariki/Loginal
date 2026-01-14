def get_cyberpunk_styles():
    return """
<style>
    /* 1. Global Reset & Fonts */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap');
    
    :root {
        --bg-color: #0B1220;
        --sidebar-bg: #0F1724;
        --card-bg: #0F1724;
        --accent-color: #22D3EE;
        --danger-color: #EF4444;
        
        --text-head: #E6F1F6;
        --text-primary: #E6F1F6; /* Using headline color for primary text for now */
        --text-muted: #9AA6B2;
        --border-color: #1e293b;
        
        --neon-glow: rgba(34, 211, 238, 0.18);
    }

    .stApp {
        background-color: var(--bg-color);
        font-family: 'Inter', sans-serif;
    }
    
    h1, h2, h3 {
        font-family: 'Inter', sans-serif;
        font-weight: 800;
        letter-spacing: -0.5px;
        color: var(--text-head) !important;
    }

    code, .stCodeBlock {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    /* 2. Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: var(--sidebar-bg);
        border-right: 1px solid var(--border-color);
    }
    
    /* 3. Metric Cards (Cyberpunk Style) */
    div[data-testid="stMetricValue"] {
        font-family: "JetBrains Mono", monospace;
        color: var(--accent-color);
        text-shadow: 0 0 15px var(--neon-glow);
    }
    div[data-testid="stMetricLabel"] {
        color: var(--text-muted);
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* 4. Full-Width Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        width: 100%;
        background-color: var(--card-bg);
        padding: 6px;
        border-radius: 8px;
        border: 1px solid var(--border-color);
    }
    .stTabs [data-baseweb="tab"] {
        flex-grow: 1;
        text-align: center;
        justify-content: center;
        height: 40px;
        border-radius: 6px;
        color: var(--text-muted);
        font-weight: 600;
        border: none;
        background-color: transparent;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(34, 211, 238, 0.1) !important;
        color: var(--accent-color) !important;
        border: 1px solid rgba(34, 211, 238, 0.2);
        box-shadow: 0 0 10px var(--neon-glow);
    }
    
    /* 5. Dataframes & Tables */
    div[data-testid="stDataFrame"] {
        border: 1px solid var(--border-color);
        border-radius: 8px;
        overflow: hidden;
        background-color: var(--card-bg);
    }
    th {
        background-color: #162032 !important; /* Slightly lighter than card-bg */
        color: var(--text-head) !important;
        font-family: 'Inter', sans-serif !important;
    }
    
    /* 6. Inputs */
    .stTextInput input, .stTextArea textarea {
        background-color: #162032;
        color: var(--text-primary);
        border: 1px solid var(--border-color);
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: var(--accent-color);
        box-shadow: 0 0 0 1px var(--accent-color), 0 0 8px var(--neon-glow);
    }
    
    /* 7. Buttons */
    button[kind="primary"] {
        background: linear-gradient(135deg, #0ea5e9 0%, #22d3ee 100%);
        color: #0f172a !important; /* Dark text on bright button */
        font-weight: 700;
        border: none;
        box-shadow: 0 4px 12px rgba(34, 211, 238, 0.2);
        transition: all 0.2s;
    }
    button[kind="primary"]:hover {
        transform: translateY(-1px);
        box-shadow: 0 0 15px var(--neon-glow);
    }

    /* Apply Neon Style to File Uploader Button */
    div[data-testid="stFileUploader"] button {
        background: linear-gradient(135deg, #0ea5e9 0%, #22d3ee 100%);
        color: #0f172a !important;
        font-weight: 700;
        border: none;
        box-shadow: 0 4px 12px rgba(34, 211, 238, 0.2);
        transition: all 0.2s;
        width: 100%; /* Make it full width like the previous button */
    }
    div[data-testid="stFileUploader"] button:hover {
        transform: translateY(-1px);
        box-shadow: 0 0 15px var(--neon-glow);
        border-color: transparent !important;
        color: #0f172a !important;
    }
    
    /* 8. Sticky Header */
    .sticky-toolbar {
        position: sticky;
        top: 0;
        z-index: 900;
        background-color: rgba(11, 18, 32, 0.95); /* --bg-color with opacity */
        backdrop-filter: blur(5px);
        padding-top: 10px;
        padding-bottom: 15px;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 15px;
    }
    
    /* 9. Right Panel */
    .right-panel {
        border-left: 1px solid var(--border-color);
        padding-left: 20px;
        height: 100%;
        background-color: var(--card-bg);
    }
</style>
"""
