def get_icon_svg(name, color="#64748b", size=24):
    """
    Returns the raw SVG string for a Lucide icon.
    No external files required.
    """
    # Common SVG header for all Lucide icons (adjusted size default to 24 for headers)
    header = f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 10px;">'
    
    icons = {
        # Dashboard -> Layout Grid
        "dashboard": '<rect width="7" height="9" x="3" y="3" rx="1" /><rect width="7" height="5" x="14" y="3" rx="1" /><rect width="7" height="9" x="14" y="12" rx="1" /><rect width="7" height="5" x="3" y="16" rx="1" />',
        
        # SQL Hunter -> Database Zap
        "sql": '<ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M3 5V19A9 3 0 0 0 21 19V5" /><path d="M3 12A9 3 0 0 0 21 12" /><path d="m13 2 2 4h-4l2 4" />',
        
        # Forensics -> Microscope
        "forensics": '<path d="M6 18h8" /><path d="M3 22h18" /><path d="M14 22a7 7 0 1 0 0-14h-1" /><path d="M9 14h2" /><path d="M9 12a2 2 0 0 1-2-2V6h6v4a2 2 0 0 1-2 2Z" /><path d="M12 6V3a1 1 0 0 0-1-1H9a1 1 0 0 0-1 1v3" />',
        
        # GenAI Rule Lab -> Sparkles
        "ai": '<path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275Z" /><path d="M5 3 4 6 1 7 4 8 5 11 8 8 9 7 8 6 5 3" />',
        
        # Semantic Search -> Network (Workflow)
        "semantic": '<rect width="8" height="8" x="3" y="3" rx="2" /><path d="M7 11v4a2 2 0 0 0 2 2h4" /><rect width="8" height="8" x="13" y="13" rx="2" />',
        
        # Settings -> Settings (Cog)
        "settings": '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.47a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" /><circle cx="12" cy="12" r="3" />',
        
        # Export -> Download
        "export": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" x2="12" y1="15" y2="3" />',
        
        # Enrich/VT -> Shield Check
        "enrich": '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /><path d="m9 12 2 2 4-4" />',
        
        # Explain -> Bot
        "explain": '<path d="M12 8V4H8" /><rect width="16" height="12" x="4" y="8" rx="2" /><path d="M2 14h2" /><path d="M20 14h2" /><path d="M15 13v2" /><path d="M9 13v2" />',
        
        # Connect -> Plug
        "connect": '<path d="M12 22v-5" /><path d="M9 8V2" /><path d="M15 8V2" /><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z" />',
        
        # Disconnect -> Unplug
        "disconnect": '<path d="m19 5 3-3" /><path d="m2 22 3-3" /><path d="M6.3 20.3a3 3 0 0 0 4.2 0L16.9 14" /><path d="M9 8V2" /><path d="M15 8V2" /><path d="M18 8v5a4 4 0 0 1-1.2 2.8" /><path d="M12 22v-5" />'

    }
    
    path = icons.get(name, "")
    if not path:
        return ""
        
    return f"{header}{path}</svg>"

def get_logo_svg(variant="shield", size=40):
    """
    Returns the raw SVG for the Loginal Brand Logo.
    Style: Neon Cyan (#22d3ee) stroke on Dark (#0f172a) fill.
    """
    # Neon Cyan color
    cyan = "#22d3ee"
    dark_bg = "#0f172a" 
    
    header = f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{cyan}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    
    logos = {
        # Option A: Shield with "L"
        "shield": f'''
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="{dark_bg}" />
            <path d="M9 8v8h6" stroke-width="3" />
        ''',
        # Option B: Circle with "L"
        "circle": f'''
            <circle cx="12" cy="12" r="10" fill="{dark_bg}" />
            <path d="M9 8v8h6" stroke-width="3" />
        '''
    }
    
    path = logos.get(variant, logos["shield"])
    return f"{header}{path}</svg>"
