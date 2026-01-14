import streamlit as st
import pandas as pd
import os
import duckdb
import json
import base64
import requests
import re
from typing import List
from datetime import datetime

# Import Loginal Core
from loginal.gui.services import MockLogService
from loginal.gui.models import GUILogEvent
# Removed unused: asyncio, RealLogService, URLAnalyzer

# Import Utils
from loginal.utils.patterns import Patterns

# Import AI Module
try:
    from loginal.ai.gateway import AIGateway
    HAS_AI = True
except ImportError:
    HAS_AI = False

# Import Semantic Module
try:
    from loginal.semantic.embeddings import LogEmbedder
    from loginal.semantic.index import VectorIndex
    from loginal.semantic.store import MetadataStore
    from loginal.semantic.cluster import LogClusterer
    import plotly.express as px
    HAS_SEMANTIC = True
except ImportError as e:
    print(f"Semantic Import Error: {e}")
    HAS_SEMANTIC = False

# Import Incident Module
try:
    from loginal.incident.model import Incident, Provenance
    from loginal.incident.store import IncidentStore
    HAS_INCIDENT = True
except ImportError as e:
    HAS_INCIDENT = False

# Import Styling
from loginal.gui.styles import get_cyberpunk_styles
from loginal.gui.icons import get_icon_svg, get_logo_svg

# Page Config
st.set_page_config(
    page_title="Loginal Control Center",
    page_icon=os.path.join(os.path.dirname(__file__), 'assets', 'logo.png'),
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject CSS
st.markdown(get_cyberpunk_styles(), unsafe_allow_html=True)

# ---------------------------------------------------------
# CONSTANTS & ASSETS
# ---------------------------------------------------------
LOGO_PATH = os.path.join(os.path.dirname(__file__), 'assets', 'logo.png')

VT_ICON_SVG = """
<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 64 64" fill="none">
<path d="M29.06 32L0 61.257h64V2.743H0zm29.09 23.406H13.53l23.94-23.552-23.296-23.26H58.15z" fill="#3b61ff"/>
</svg>
"""

# ---------------------------------------------------------
# CACHED UTILITIES
# ---------------------------------------------------------

@st.cache_data(show_spinner=False)
def get_image_base64(path):
    """Encodes image to base64 for HTML embedding."""
    try:
        with open(path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode()
        return f"data:image/png;base64,{encoded_string}"
    except Exception:
        return ""

def parse_uploaded_file(uploaded_file) -> List[dict]:
    """Parses log file."""
    try:
        content = uploaded_file.read()
        filename = uploaded_file.name.lower()
        text = str(content, 'utf-8', errors='ignore')
        lines = text.split('\n')
        
        parsed = []
        import json
        
        custom_pattern = r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+(\w+)\s+\[(.*?)\]\s+(.*?):(.*)$'
        
        for line in lines:
            line = line.strip()
            if not line: continue
            
            match = re.match(custom_pattern, line)
            if match:
                ts_str, level, component, logger, payload = match.groups()
                try:
                    ts_clean = ts_str.replace(',', '.')
                    dt = datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S.%f")
                except:
                    dt = datetime.now()

                kv_pairs = {}
                parts = payload.strip().split(' ')
                clean_msg = payload.strip()
                for p in parts:
                    if '=' in p:
                        parts_k_v = p.split('=', 1)
                        if len(parts_k_v) == 2:
                            kv_pairs[parts_k_v[0]] = parts_k_v[1]
                
                sev = kv_pairs.get('severity', level).lower()
                if sev == "warn": sev = "medium"
                if sev == "error": sev = "high"
                
                parsed.append({
                    "timestamp": dt.isoformat(),
                    "severity": sev,
                    "event_type": component,
                    "message": clean_msg,
                    "host": kv_pairs.get('host', 'server-01'),
                    "user": kv_pairs.get('user', 'unknown'),
                    "source_ip": kv_pairs.get('src_ip', None),
                    "destination_ip": kv_pairs.get('dst_ip', None),
                    "domain": kv_pairs.get('domain', None)
                })
                continue

            try:
                json_obj = json.loads(line)
                parsed.append(json_obj)
                continue
            except:
                pass

            parsed.append({
                "timestamp": datetime.now().isoformat(),
                "severity": "info",
                "event_type": "LogEntry",
                "message": line,
                "host": "unknown-host",
                "user": "system"
            })
            
        return parsed
    except Exception as e:
        st.error(f"Error parsing file: {e}")
        return []

@st.cache_data(show_spinner=False)
def get_metrics_cached(logs: List[dict]):
    df = pd.DataFrame(logs)
    if df.empty:
        return 0, 0, 0, 0
    
    total = len(df)
    threats = len(df[df['severity'].isin(['critical', 'high'])]) if 'severity' in df.columns else 0
    sources = df['host'].nunique() if 'host' in df.columns else 0
    load = min(total // 100, 100)
    return total, threats, sources, load

class StreamlitApp:
    def __init__(self):
        if 'logs' not in st.session_state:
            st.session_state.logs = []
        if 'service' not in st.session_state:
            st.session_state.service = MockLogService()
        
        # AI State
        if 'ai_gateway' not in st.session_state and HAS_AI:
            recovered_key = st.session_state.get('gemini_api_key') or os.getenv("LOGINAL_GEMINI_KEY")
            if recovered_key:
                st.session_state.gemini_api_key = recovered_key
                st.session_state.ai_gateway = AIGateway(api_key=recovered_key)
            else:
                 st.session_state.ai_gateway = None

        if 'bulk_analysis' not in st.session_state:
            st.session_state.bulk_analysis = None
        if 'expert_rule' not in st.session_state:
            st.session_state.expert_rule = None
            
        # Interactive Results State
        if 'active_explanation' not in st.session_state:
            st.session_state.active_explanation = None
        if 'active_scan' not in st.session_state:
            st.session_state.active_scan = None
        if 'active_similars' not in st.session_state:
            st.session_state.active_similars = None

        # Semantic State (Global Init)
        if 'semantic_idx' not in st.session_state:
            if HAS_SEMANTIC:
                st.session_state.semantic_idx = VectorIndex()
                st.session_state.semantic_store = MetadataStore()
                st.session_state.semantic_embedder = None
            else:
                st.session_state.semantic_idx = None
                st.session_state.semantic_store = None
                st.session_state.semantic_embedder = None

    def run(self):
        self._build_sidebar()
        self._build_main_area()

    def _handle_file_upload(self, uploaded_file):
        with st.spinner("Parsing & Indexing..."):
            new_logs = parse_uploaded_file(uploaded_file)
            st.session_state.logs = new_logs
            st.success(f"Loaded {len(new_logs)} events from {uploaded_file.name}")
            st.rerun()

    def _build_sidebar(self):
        img_b64 = get_image_base64(LOGO_PATH)
        icon_html = f'<img src="{img_b64}" width="42" height="42" style="border-radius: 8px;">' if img_b64 else '<div style="font-size: 32px;">🛡️</div>'
        
        with st.sidebar:
            st.markdown(f"""
            <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                {icon_html}
                <h2 style="margin: 0; font-family: 'Segoe UI', sans-serif; letter-spacing: 2px; font-weight: 700; color: #f8fafc;">LOGINAL</h2>
            </div>
            """, unsafe_allow_html=True)
            
            st.caption("Advanced Threat Sim & Hunting")
            st.divider()
            
            st.subheader("Operations")
            uploaded = st.file_uploader("Ingest Log File", type=["json", "log", "csv", "txt"], label_visibility="collapsed")
            if uploaded:
                 if uploaded.file_id != st.session_state.get('last_uploaded_id'):
                     st.session_state.last_uploaded_id = uploaded.file_id
                     self._handle_file_upload(uploaded)

            st.divider()
            st.subheader("Global Filters")
            st.info("Applies to Dashboard Only")
            
            st.divider()
            with st.expander("System Status", expanded=True):
                 mem = 0
                 if st.session_state.logs:
                     import sys
                     mem = sys.getsizeof(st.session_state.logs) / 1024 / 1024
                 st.caption(f"Memory: {mem:.2f} MB")
                 st.caption(f"Events: {len(st.session_state.logs)}")
                 
                 if st.button("Clear Memory", type="secondary"):
                     st.session_state.logs = []
                     st.rerun()

    def _build_main_area(self):
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Dashboard", "SQL Hunter", "Forensics Lab", "GenAI Rule Lab", "Semantic Search", "Settings"])
        
        with tab1:
            self._render_dashboard_tab()
        with tab2:
            self._render_sql_tab()
        with tab3:
            self._render_forensics_tab()
        with tab4:
            self._render_ai_lab_tab()
        with tab5:
            self._render_semantic_tab()
        with tab6:
            self._render_settings_tab()

    def _render_dashboard_tab(self):
        st.markdown(f"## {get_icon_svg('dashboard', '#f8fafc')} Dashboard", unsafe_allow_html=True)

        total, threats, sources, load = get_metrics_cached(st.session_state.logs)
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Events", total)
        c2.metric("Threat Alerts", threats, delta=threats if threats > 0 else None, delta_color="inverse")
        c3.metric("Active Sources", sources)
        c4.metric("System Load", f"{load}%")
        
        if total == 0:
            st.info("Waiting for data...")
            return

        df = pd.DataFrame(st.session_state.logs)

        # Charts
        with st.expander("📊 Visualizations", expanded=False):
             c_chart1, c_chart2 = st.columns(2)
             with c_chart1:
                 st.bar_chart(df['severity'].value_counts(), color=["#ef4444"])
             with c_chart2:
                 if 'timestamp' in df.columns:
                     try:
                         df['timestamp'] = pd.to_datetime(df['timestamp'])
                         st.line_chart(df.set_index('timestamp').resample('1min').size(), color="#22d3ee")
                     except: pass
        
        st.write("")

        # Sticky Toolbar
        st.markdown('<div class="sticky-toolbar">', unsafe_allow_html=True)
        t1, t2, t3 = st.columns([2, 2, 2])
        with t1:
             search_term = st.text_input("🔍 Quick Filter", placeholder="Host, User or IP...", label_visibility="collapsed")
        with t2:
             sev_filter = st.multiselect("Severity", ["medium", "high", "critical"], default=[], placeholder="All Severities", label_visibility="collapsed")
        with t3:
             limit = st.select_slider("Rows", options=[100, 500, 1000, 5000], value=1000, label_visibility="collapsed")
        st.markdown('</div>', unsafe_allow_html=True)

        # Filter Logic
        display_df = df
        if search_term:
             mask = pd.Series([False] * len(display_df))
             for col in ['host', 'user', 'message', 'source_ip']:
                 if col in display_df.columns:
                     mask |= display_df[col].fillna('').astype(str).str.contains(search_term, case=False)
             display_df = display_df[mask]
        
        if sev_filter:
             display_df = display_df[display_df['severity'].isin(sev_filter)]
             
        display_df = display_df.head(int(limit))

        # Fragment Call
        self._render_interactive_dashboard_content(display_df)

        st.divider()
        st.markdown(f"### {get_icon_svg('export', '#94a3b8')} Data Export", unsafe_allow_html=True)
        st.download_button("Download CSV Report", df.to_csv(index=False).encode('utf-8'), "loginal_export.csv", "text/csv", key='download-csv')



    @st.fragment
    def _render_interactive_dashboard_content(self, display_df):
        st.caption(f"Showing {len(display_df)} events")
        
        def highlight_severity(val):
            s = str(val).lower()
            if s == 'critical': return 'background-color: #450a0a; color: #f87171'
            elif s == 'high': return 'color: #fb923c'
            elif s == 'medium': return 'color: #facc15'
            return ''

        display_cols = ['timestamp', 'severity', 'event_type', 'host', 'message']
        final_cols = [c for c in display_cols if c in display_df.columns]

        # Main DataFrame
        event = st.dataframe(
            display_df[final_cols].style.map(highlight_severity, subset=['severity']),
            height=400,
            width='stretch',
            on_select="rerun",
            selection_mode="single-row"
        )
        
        if event.selection.rows:
            idx = event.selection.rows[0]
            selected_data = display_df.iloc[idx].to_dict()
            
            # CHECK TRANSITION
            current_id = str(selected_data.get('timestamp')) + str(selected_data.get('message', ''))
            old_id = None
            if st.session_state.get('forensic_props'):
                 old = st.session_state.forensic_props
                 old_id = str(old.get('timestamp')) + str(old.get('message', ''))
            
            if current_id != old_id:
                 # New Row Selected -> Reset Details State
                 st.session_state.forensic_props = selected_data
                 st.session_state.active_explanation = None
                 st.session_state.active_scan = None
                 st.session_state.active_similars = None
                 st.rerun()

        active_row = st.session_state.get('forensic_props')

        # Detail Panel
        col_details = st.container()
        with col_details:
             if active_row:
                 st.markdown('<div class="right-panel">', unsafe_allow_html=True)
                 
                 d_head, d_close = st.columns([4, 1])
                 d_head.subheader("Event Details")
                 if d_close.button("✖ Close Details", key="close_details_frag"):
                     st.session_state.forensic_props = None
                     st.session_state.active_explanation = None
                     st.session_state.active_scan = None
                     st.session_state.active_similars = None
                     st.rerun()
                 
                 r = active_row
                 st.info(f"{r.get('message')}")
                 
                 md1, md2 = st.columns(2)
                 md1.text_input("Host", r.get('host'), disabled=True, key="dash_host_frag")
                 md2.text_input("User", r.get('user'), disabled=True, key="dash_user_frag")
                 md1.text_input("IP", r.get('source_ip', 'N/A'), disabled=True, key="dash_ip_frag")
                 md2.text_input("Process", r.get('process_name', 'N/A'), disabled=True, key="dash_proc_frag")
                 
                 st.divider()
                 st.caption("Actions")
                 
                 act1, act2, act3, act4 = st.columns(4)
                 
                 # 1. FORENSICS
                 with act1:
                     st.markdown(f"**Forensics**")
                     if st.button("🔬 Analyze", use_container_width=True, key="btn_analyze_frag"):
                         st.session_state.target_forensic_event = r
                         st.success("Sent to Lab! Switch tab ->")

                 # 2. IOC ENRICHMENT
                 import re
                 text = str(r.get('message', '')) + " " + str(r.get('host', ''))
                 
                 # USE CENTRAL PATTERNS
                 found_iocs_map = Patterns.get_all_iocs(text)
                 found_iocs = []
                 for kind, vals in found_iocs_map.items():
                     for v in vals:
                         found_iocs.append({"kind": kind, "val": v})

                 with act2:
                     st.markdown(f"**Threat Intel**")
                     if found_iocs:
                         if st.button(f"Scan {len(found_iocs)} IOCs", key="btn_scan_all_frag", use_container_width=True):
                             vt_key = st.session_state.get('vt_api_key')
                             if not vt_key:
                                 st.session_state.active_scan = [{"error": "API Key Missing. Configure in Settings."}]
                                 st.rerun()
                             else:
                                 with st.status(f"Scanning {len(found_iocs)} IOCs...", expanded=True) as status:
                                     rich_results = []
                                     for ioc in found_iocs:
                                         status.write(f"Checking {ioc['kind']}: {ioc['val']}...")
                                         url = ""
                                         if ioc['kind'] == 'IP':
                                             url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc['val']}"
                                         elif ioc['kind'] == 'Domain':
                                             url = f"https://www.virustotal.com/api/v3/domains/{ioc['val']}"
                                         elif ioc['kind'] in ['MD5', 'SHA1', 'SHA256']:
                                             url = f"https://www.virustotal.com/api/v3/files/{ioc['val']}"
                                         
                                         if url:
                                             try:
                                                 resp = requests.get(url, headers={"x-apikey": vt_key}, timeout=5)
                                                 if resp.status_code == 200:
                                                     data = resp.json()
                                                     attrs = data.get('data', {}).get('attributes', {})
                                                     stats = attrs.get('last_analysis_stats', {})
                                                     
                                                     rich_results.append({
                                                         "ioc": ioc['val'],
                                                         "malicious": stats.get('malicious', 0),
                                                         "suspicious": stats.get('suspicious', 0),
                                                         "harmless": stats.get('harmless', 0),
                                                         "undetected": stats.get('undetected', 0),
                                                         "reputation": attrs.get('reputation', 0),
                                                         "total": sum(stats.values())
                                                     })
                                                 elif resp.status_code == 404:
                                                      rich_results.append({"error": f"{ioc['val']}: Not Found in VT"})
                                                 else:
                                                     rich_results.append({"error": f"{ioc['val']}: HTTP {resp.status_code}"})
                                             except Exception as e:
                                                 rich_results.append({"error": f"{ioc['val']}: Connection Failed"})
                                         else:
                                              rich_results.append({"error": f"{ioc['val']}: Type {ioc['kind']} not supported yet"})
                                     
                                     status.update(label="Scan Complete", state="complete", expanded=False)
                                     st.session_state.active_scan = rich_results
                                     st.rerun()
                                     
                 # 3. AI EXPLAIN
                 with act3:
                      st.markdown(f"**AI Analyst**")
                      if st.button("Explain", type="primary", use_container_width=True, key="btn_explain_frag"):
                           if not HAS_AI or not st.session_state.get('ai_gateway'):
                                st.error("AI Not Configured")
                           else:
                                with st.status("Analyzing Event...", expanded=True) as status:
                                    status.write("Generating prompt...")
                                    expl = st.session_state.ai_gateway.explain_event(r)
                                    status.write("Parsing response...")
                                    st.session_state.active_explanation = expl
                                    status.update(label="Analysis Ready", state="complete", expanded=False)
                                st.rerun()

                 # 4. FIND SIMILAR
                 with act4:
                     st.markdown(f"**Semantic**")
                     if st.button("Find Similar", use_container_width=True, key="btn_similar_frag"):
                          if not HAS_SEMANTIC:
                              st.error("Missing Libraries")
                          else:
                                   with st.status("Searching Knowledge Base...", expanded=True) as status:
                                       if not st.session_state.get('semantic_embedder'):
                                            status.write("Loading Embedder Model...")
                                            st.session_state.semantic_embedder = LogEmbedder()
                                       
                                       is_empty = False
                                       if st.session_state.semantic_idx:
                                            if hasattr(st.session_state.semantic_idx, 'next_id'):
                                                 if st.session_state.semantic_idx.next_id == 0: is_empty = True
                                            else:
                                                 is_empty = True
                                       
                                       if is_empty or st.session_state.semantic_store.count() == 0:
                                            status.write("Indexing logs (auto-building vector store)...")
                                            candidates = st.session_state.logs
                                            if candidates:
                                                st.session_state.semantic_store.clear()
                                                st.session_state.semantic_idx = VectorIndex()
                                                
                                                vectors = st.session_state.semantic_embedder.embed_logs(candidates, batch_size=128)
                                                start_id = st.session_state.semantic_idx.add_vectors(vectors)
                                                st.session_state.semantic_store.add_batch(start_id, candidates)
                                            else:
                                                status.update(label="No Data", state="error")
                                                st.warning("No logs to index.")
                                                st.rerun()

                                       status.write("Encoding Query...")
                                       q = r.get('message', '')
                                       q_vec = st.session_state.semantic_embedder.embed_logs([q])
                                       
                                       status.write("Searching Index...")
                                       ids, scores = st.session_state.semantic_idx.search(q_vec, k=5)
                                       
                                       try:
                                           recs = st.session_state.semantic_store.get_batch(ids)
                                           st.session_state.active_similars = pd.DataFrame(recs)
                                           status.update(label="Found Similar Events", state="complete", expanded=False)
                                       except:
                                           st.warning("Index error. Matches found but metadata missing.")

                 # --- DISPLAY RESULTS AREA ---
                 
                 # Explanation Result
                 if st.session_state.get('active_explanation'):
                     exp = st.session_state.active_explanation
                     st.divider()
                     st.markdown(f"#### 🤖 AI Analysis")
                     if exp.get('is_malicious'):
                         st.error(f"⚠️ **Malicious (Confidence: {exp.get('confidence')})**")
                     else:
                         st.success(f"**Benign (Confidence: {exp.get('confidence')})**")
                     st.write(exp.get('explanation'))
                     if st.button("Clear Analysis", key="clr_ai"):
                         st.session_state.active_explanation = None
                         st.rerun()

                 # Scan Result (RICH NEON CARD)
                 if st.session_state.get('active_scan'):
                     st.divider()
                     
                     st.markdown(f"""
                     <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
                         <div style="width: 32px; height: 32px;">{VT_ICON_SVG}</div>
                         <h3 style="margin: 0; color: #fff; font-weight: 600;">VirusTotal Intelligence</h3>
                     </div>
                     """, unsafe_allow_html=True)
                     
                     results = st.session_state.active_scan
                     for res in results:
                         if "error" in res:
                             st.error(res['error'])
                             continue
                         
                         mal = res.get('malicious', 0)
                         total = res.get('total', 90)
                         pct = min((mal / total) * 100, 100) if total > 0 else 0
                         
                         color = "#ef4444" if mal > 0 else "#22c55e" # Red or Green
                         bg_color_op = "rgba(239, 68, 68, 0.1)" if mal > 0 else "rgba(34, 197, 94, 0.1)"
                         
                         card_html = f"""
                         <div style="
                            background: linear-gradient(145deg, #1e293b, #0f172a);
                            border: 1px solid {color};
                            padding: 20px;
                            border-radius: 12px;
                            margin-bottom: 10px;
                            box-shadow: 0 4px 20px {bg_color_op};
                         ">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <h3 style="margin:0; color: #fff; font-family: monospace;">{res['ioc']}</h3>
                                <div style="text-align:right;">
                                    <span style="font-size: 2em; font-weight:bold; color: {color}; text-shadow: 0 0 10px {color};">
                                        {mal}
                                    </span>
                                    <span style="color: #64748b; font-size: 1.2em;">/ {total}</span>
                                </div>
                            </div>
                            
                            <!-- PROGRESS BAR -->
                            <div style="height: 8px; width: 100%; background: #334155; border-radius: 4px; margin: 15px 0; overflow:hidden;">
                                <div style="width: {pct if mal > 0 else 100}%; height: 100%; background: {color}; box-shadow: 0 0 10px {color}; transition: width 0.5s ease;"></div>
                            </div>

                            <div style="display:flex; justify-content:space-between; color: #94a3b8; font-size: 0.9em; font-family: sans-serif;">
                                <span>Harmless: <strong style="color: #22c55e">{res['harmless']}</strong></span>
                                <span>Suspicious: <strong style="color: #f59e0b">{res['suspicious']}</strong></span>
                                <span>Untracked: {res['undetected']}</span>
                                <span>Rep: {res['reputation']}</span>
                            </div>
                         </div>
                         """
                         st.markdown(card_html, unsafe_allow_html=True)

                     if st.button("Clear Scan", key="clr_scan"):
                         st.session_state.active_scan = None
                         st.rerun()

                 # Similar Result
                 if st.session_state.get('active_similars') is not None:
                     df_sim = st.session_state.active_similars
                     st.divider()
                     st.markdown(f"#### 🧩 Similar Events")
                     if df_sim.empty:
                         st.info("No similar events found.")
                     else:
                         st.dataframe(df_sim[['timestamp', 'message']], hide_index=True)
                     if st.button("Clear Search", key="clr_sim"):
                         st.session_state.active_similars = None
                         st.rerun()
                         
                 st.markdown('</div>', unsafe_allow_html=True)

    def _render_sql_tab(self):
        st.markdown(f"## {get_icon_svg('sql', '#fbbf24')} SQL Hunter", unsafe_allow_html=True)
        st.caption("Powered by DuckDB. Query your logs using standard SQL. Table name is `logs`.")
        
        df = pd.DataFrame(st.session_state.logs)
        if df.empty:
            st.warning("No data to query.")
            return

        col1, col2 = st.columns([1, 3])
        with col1:
             st.markdown("##### Quick Queries")
             option = st.radio("Templates", [
                 "Select Custom...",
                 "Top Event Types",
                 "Critical Events by Host",
                 "User Activity Summary"
             ], label_visibility="collapsed")
        
        query = "SELECT * FROM logs LIMIT 10"
        if option == "Top Event Types":
            query = "SELECT event_type, count(*) as count FROM logs GROUP BY event_type ORDER BY count DESC"
        elif option == "Critical Events by Host":
            query = "SELECT host, count(*) as threats FROM logs WHERE severity IN ('critical', 'high') GROUP BY host"
        elif option == "User Activity Summary":
             query = "SELECT user, count(DISTINCT host) as hosts_accessed, count(*) as events FROM logs GROUP BY user"

        with col2:
            sql_input = st.text_area("SQL Query", value=query, height=150)
            
        if st.button("Run Query", type="primary", use_container_width=True):
            try:
                logs = df 
                result = duckdb.sql(sql_input).df()
                st.dataframe(result, width='stretch')
            except Exception as e:
                st.error(f"SQL Error: {e}")

    def _render_forensics_tab(self):
        st.markdown(f"## {get_icon_svg('forensics', '#22d3ee')} Forensics Lab", unsafe_allow_html=True)
        st.caption("Deep-dive analysis of specific artifacts and events.")
        
        # CONSUME SIGNAL FROM DASHBOARD
        if st.session_state.get('target_forensic_event'):
            st.session_state.forensic_props = st.session_state.target_forensic_event
            st.session_state.target_forensic_event = None
            st.rerun()
        
        with st.expander("📂 Select Event for Analysis", expanded=True):
            if not st.session_state.logs:
                st.warning("No logs loaded.")
                return

            search_q = st.text_input("Search Logs", placeholder="Filter by host, user, or message content...", key="forensic_search")
            
            df = pd.DataFrame(st.session_state.logs)
            if search_q:
                mask = df.astype(str).apply(lambda x: x.str.contains(search_q, case=False)).any(axis=1)
                display_df = df[mask]
            else:
                display_df = df

            st.caption(f"Showing {len(display_df)} events")
            selection = st.dataframe(display_df, width='stretch', height=250, on_select="rerun", selection_mode="single-row", key="forensic_selector")

        if 'forensic_props' not in st.session_state:
            st.session_state.forensic_props = None

        if selection.selection.rows:
            idx = selection.selection.rows[0]
            st.session_state.forensic_props = display_df.iloc[idx].to_dict()

        if st.session_state.forensic_props:
            row = st.session_state.forensic_props
            st.divider()
            c_head, c_clear = st.columns([4, 1])
            with c_head:
                st.subheader("🔬 Analysis Workspace")
            with c_clear:
                if st.button("Clear Selection", key="clear_forensics"):
                    st.session_state.forensic_props = None
                    st.rerun()

            t_facts, t_artifacts, t_context, t_timeline = st.tabs(["1. Structured Facts", "2. Artifacts & IOCs", "3. Deep Context", "4. Evidence Timeline"])
            
            with t_facts:
                st.markdown("#### Event Normalization")
                f1, f2, f3 = st.columns(3)
                f1.text_input("Timestamp", value=str(row.get('timestamp', 'N/A')), disabled=True, key="for_ts")
                f1.text_input("Severity", value=str(row.get('severity', 'N/A')).upper(), disabled=True, key="for_sev")
                f2.text_input("Host", value=str(row.get('host', 'N/A')), disabled=True, key="for_host")
                f2.text_input("User", value=str(row.get('user', 'N/A')), disabled=True, key="for_user")
                f3.text_input("Source", value=str(row.get('source', 'Loginal')), disabled=True, key="for_src")
                f3.text_input("Process", value=str(row.get('process_name', 'N/A')), disabled=True, key="for_proc")
                st.text_area("Full Message", value=str(row.get('message', '')), height=100, disabled=True, key="for_msg")
                with st.expander("Raw JSON Data"):
                    st.json(row)

            with t_artifacts:
                st.markdown("#### Automated Extraction")
                message = str(row.get('message', '')) + " " + str(row.get('command_line', ''))
                patterns = {
                    "IPv4": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                    "URL": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*',
                    "Domain": r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
                    "Base64": r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
                }
                # import re (Moved to global)
                found = False

                for label, pat in patterns.items():
                    matches = list(set(re.findall(pat, message)))
                    if matches:
                        found = True
                        st.markdown(f"**{label} Found:**")
                        for m in matches:
                            c1, c2 = st.columns([3, 1])
                            c1.code(m, language="text")
                            if label == "Base64":
                                try:
                                    decoded = base64.b64decode(m).decode('utf-8', errors='replace')
                                    with c1:
                                        st.caption("Decoded Result:")
                                        st.code(decoded, language="text")
                                except:
                                    c1.caption("Decoding failed (might be binary)")
                if not found:
                    st.info("No common IOCs or artifacts detected.")

            with t_context:
                target_host = row.get('host')
                target_user = row.get('user')
                current_ts = pd.to_datetime(row.get('timestamp'))

                # Prepare DataFrame
                ctx_df = df.copy()
                ctx_df['dt'] = pd.to_datetime(ctx_df['timestamp'], errors='coerce')
                ctx_df = ctx_df.sort_values('dt')
                
                # Filter for same Entity context
                mask_entity = pd.Series([False] * len(ctx_df))
                if target_host: mask_entity |= (ctx_df['host'] == target_host)
                if target_user: mask_entity |= (ctx_df['user'] == target_user)
                entity_df = ctx_df[mask_entity].reset_index(drop=True)
                
                # Find current event index in entity_df
                # We match by exact timestamp and message to find "this" event
                matches = entity_df[
                    (entity_df['dt'] == current_ts) & 
                    (entity_df['message'] == row.get('message'))
                ]
                
                curr_idx = matches.index[0] if not matches.empty else -1

                col_cause, col_diff = st.columns([1, 1])
                
                # 1. CAUSALITY VIEW
                with col_cause:
                    st.markdown("#### 🔗 Causality View")
                    st.caption("Sequence of events for this Host/User")
                    
                    if curr_idx != -1:
                        # Preceded By
                        prev_events = entity_df.iloc[max(0, curr_idx-2):curr_idx]
                        if not prev_events.empty:
                            st.markdown("**Preceded by:**")
                            for _, p_evt in prev_events.iterrows():
                                delta = (current_ts - p_evt['dt']).total_seconds()
                                st.markdown(f"- `{p_evt['event_type']}` ({p_evt['user']}) – **{int(delta)}s before**")
                        else:
                            st.caption("(No immediate previous events)")
                        
                        st.markdown(f"➤ **{row.get('event_type', 'Current Event')}** (THIS EVENT)")

                        # Followed By
                        next_events = entity_df.iloc[curr_idx+1:curr_idx+3]
                        if not next_events.empty:
                            st.markdown("**Followed by:**")
                            for _, n_evt in next_events.iterrows():
                                delta = (n_evt['dt'] - current_ts).total_seconds()
                                st.markdown(f"- `{n_evt['event_type']}` ({n_evt['user']}) – **{int(delta)}s after**")
                        else:
                            st.caption("(No immediate following events)")
                    else:
                        st.warning("Could not locate event in timeline.")

                # 2. FIELD DIFFING
                with col_diff:
                    st.markdown("### Field Changes")
                    if curr_idx > 0:
                        prev_evt = entity_df.iloc[curr_idx-1]
                        st.caption(f"Comparing vs previous event ({prev_evt['event_type']})")
                        
                        diffs_found = False
                        fields_to_check = ['event_type', 'user', 'source_ip', 'process_name', 'host', 'severity']
                        
                        for f in fields_to_check:
                            v_curr = str(row.get(f, 'N/A'))
                            v_prev = str(prev_evt.get(f, 'N/A'))
                            
                            if v_curr != v_prev:
                                diffs_found = True
                                st.markdown(f"**{f}** changed:")
                                st.code(f"{v_prev} → {v_curr}", language="text")
                        
                        if not diffs_found:
                            st.info("No key fields changed from previous event.")
                    else:
                        st.info("No previous event to compare.")

                st.divider()
                
                # 3. ENTITY HEATMAP
                st.markdown("#### 📊 Entity Activity Heatmap")
                if not entity_df.empty:
                    heatmap_df = entity_df.copy()
                    heatmap_df['minute'] = heatmap_df['dt'].dt.floor('min')
                    stats = heatmap_df.groupby('minute').size().rename('Events')
                    
                    st.bar_chart(stats, height=200, color="#a855f7")
                else:
                    st.info("Not enough data for heatmap.")


            with t_timeline:
                st.markdown("#### Contextual Timeline (±5 min)")
                try:
                    if pd.isna(current_ts):
                        st.error("Invalid timestamp.")
                    else:
                        start_time = current_ts - pd.Timedelta(minutes=5)
                        end_time = current_ts + pd.Timedelta(minutes=5)
                        timeline_df = df.copy()
                        timeline_df['dt'] = pd.to_datetime(timeline_df['timestamp'], errors='coerce')
                        target_host = row.get('host')
                        target_user = row.get('user')
                        mask_time = (timeline_df['dt'] >= start_time) & (timeline_df['dt'] <= end_time)
                        mask_entity = pd.Series([False] * len(timeline_df))
                        if target_host: mask_entity |= (timeline_df['host'] == target_host)
                        if target_user: mask_entity |= (timeline_df['user'] == target_user)
                            
                        final_df = timeline_df[mask_time & mask_entity].sort_values('dt')
                        
                        if final_df.empty:
                            st.warning("No related events found.")
                        else:
                            st.caption(f"Found {len(final_df)} events related to {target_host} / {target_user}")
                            st.dataframe(final_df[['timestamp', 'severity', 'event_type', 'message']], width='stretch', hide_index=True)
                            st.line_chart(final_df.set_index('dt')['severity'].apply(lambda x: 3 if x=='critical' else (2 if x=='high' else 1)))
                except Exception as e:
                    st.error(f"Timeline Error: {e}")
        else:
            st.info("👈 Select an event to start.")

    def _render_ai_lab_tab(self):
        st.markdown(f"## {get_icon_svg('ai', '#a855f7')} GenAI Rule Lab", unsafe_allow_html=True)
        
        if not HAS_AI:
            st.error("Google Generative AI SDK not found. Please install `google-generativeai`.")
            return

        if not st.session_state.get('gemini_api_key'):
            st.warning("Google Gemini API Key not configured.")
            return

        with st.container():
            c1, c2 = st.columns([3, 1])
            with c1:
                st.subheader("1. Input Context")
            with c2:
                if st.button("Clear Session", type="secondary"):
                    st.session_state.bulk_analysis = None
                    st.session_state.expert_rule = None
                    st.session_state.samples_cache = None
                    st.rerun()

            rule_desc = st.text_input("Description (What are we detecting?)", placeholder="e.g. Brute Force on SSH")

            if not st.session_state.logs:
                st.info("No logs loaded.")
            else:
                df = pd.DataFrame(st.session_state.logs)
                cols = [c for c in ['timestamp', 'severity', 'event_type', 'message'] if c in df.columns] or df.columns.tolist()
                selection = st.dataframe(df[cols], width='stretch', on_select="rerun", selection_mode="multi-row", height=300, key="genai_log_selector")
                
                selected_indices = selection.selection.rows
                selected_rows = df.iloc[selected_indices] if selected_indices else pd.DataFrame()

                st.divider()
                col_act1, col_act2, col_act3 = st.columns([1, 2, 1])
                with col_act2:
                    if st.button("Step 2: Analyze Patterns (Bulk Layer)", type="primary", use_container_width=True):
                        if selected_rows.empty:
                            st.warning("Please select at least one log row.")
                        else:
                            with st.spinner(f"Analyzing {len(selected_rows)} selected logs..."):
                                lines = []
                                for _, row in selected_rows.iterrows():
                                    lines.append(str(row.get('message', row.to_json())))
                                
                                delimiter_hint = "TABS (\\t)" if lines and "\t" in lines[0] else "UNKNOWN"
                                res = st.session_state.ai_gateway.analyze_bulk(lines, delimiter_hint=delimiter_hint)
                                st.session_state.bulk_analysis = res
                                st.session_state.samples_cache = lines

        st.divider()
        c_left, c_right = st.columns(2)
        
        with c_left:
            st.subheader("2. Pattern Analysis")
            if st.session_state.bulk_analysis:
                raw_res = st.session_state.bulk_analysis
                if "extracted_fields" in raw_res:
                    st.caption("Extracted Schema")
                    field_df = pd.DataFrame({"Field Name": raw_res.get("extracted_fields", [])})
                    field_df["Inferred Type"] = "String/Text"
                    st.dataframe(field_df, hide_index=True, width='stretch')
                
                m1, m2 = st.columns(2)
                m1.info(f"**Format:**\n{raw_res.get('log_format', 'Unknown')}")
                m2.warning(f"**Delimiter:**\n{raw_res.get('delimiter', 'Unknown')}")
            else:
                st.info("Waiting for input...")
        
        with c_right:
            st.subheader("3. Sigma Rule Generation")
            if st.session_state.bulk_analysis:
                if st.button("Step 3: Generate Final Rule (Expert Layer)", type="primary", use_container_width=True):
                     with st.spinner("Consulting Expert Model (Pro)..."):
                        rule = st.session_state.ai_gateway.generate_rule_expert(st.session_state.samples_cache, st.session_state.bulk_analysis, rule_desc)
                        st.session_state.expert_rule = rule

            if st.session_state.expert_rule:
                st.markdown("### Final Rule")
                st.code(st.session_state.expert_rule, language="yaml")
                st.download_button(label="Download Rule (.yml)", data=st.session_state.expert_rule, file_name="generated_rule.yml", mime="application/x-yaml", type="secondary")

    def _render_semantic_tab(self):
        st.markdown(f"## {get_icon_svg('semantic', '#34d399')} Semantic & Hybrid Search", unsafe_allow_html=True)
        
        if not HAS_SEMANTIC:
            st.error("Semantic dependencies missing.")
            return

        if 'semantic_idx' not in st.session_state:
            st.session_state.semantic_idx = VectorIndex()
            st.session_state.semantic_store = MetadataStore()
            st.session_state.semantic_embedder = None 
            st.session_state.cluster_results = None

        with st.expander("Indexing Strategy", expanded=False):
            cols = st.columns([1, 2, 1])
            cols[0].metric("Indexed Documents", st.session_state.semantic_store.count())
            with cols[1]:
                idx_all = st.checkbox("Index All Events", value=False)
                idx_threats = st.checkbox("Index Threats Only", value=True)
                
            if cols[2].button("Re-Index Data", type="primary"):
                if not st.session_state.logs:
                    st.warning("No logs.")
                else:
                    with st.spinner("Building Semantic Index..."):
                        candidates = st.session_state.logs
                        if not idx_all and idx_threats:
                            candidates = [l for l in candidates if l.get('severity') in ['medium', 'high', 'critical']]
                        
                        if not candidates:
                             st.warning("No logs matched criteria.")
                        else:
                             st.session_state.semantic_store.clear()
                             st.session_state.semantic_idx = VectorIndex()
                             if not st.session_state.semantic_embedder:
                                 st.session_state.semantic_embedder = LogEmbedder()
                             vectors = st.session_state.semantic_embedder.embed_logs(candidates, batch_size=128)
                             start_id = st.session_state.semantic_idx.add_vectors(vectors)
                             st.session_state.semantic_store.add_batch(start_id, candidates)
                             st.success(f"Indexed {len(candidates)} vectors!")
                             st.rerun()

        st.divider()
        c_search, c_filters = st.columns([2, 1])
        with c_search:
            query = st.text_input("Semantic Query", placeholder="e.g. unauthorized access attempts")
        with c_filters:
            filter_host = st.text_input("Host Filter (Exact)", placeholder="web01")
        k_slider = st.slider("Results Limit (Top K)", 10, 200, 50)
        
        results_df = pd.DataFrame()
        
        if query or st.button("Run Search"):
            if st.session_state.semantic_store.count() == 0:
                st.warning("Index is empty.")
            else:
                if not st.session_state.semantic_embedder:
                    st.session_state.semantic_embedder = LogEmbedder()
                q_vec = st.session_state.semantic_embedder.embed_logs([query])
                ids, scores = st.session_state.semantic_idx.search(q_vec, k=k_slider * 2)
                
                valid_ids = None
                if filter_host:
                    valid_ids = set(st.session_state.semantic_store.filter_ids(host=filter_host))
                
                final_hits = []
                for i, score in zip(ids, scores):
                     if valid_ids is not None and i not in valid_ids: continue
                     final_hits.append((i, score))
                     if len(final_hits) >= k_slider: break
                
                if final_hits:
                    hit_ids = [x[0] for x in final_hits]
                    hit_scores = [x[1] for x in final_hits]
                    records = st.session_state.semantic_store.get_batch(hit_ids)
                    results_df = pd.DataFrame(records)
                    results_df['similarity'] = hit_scores
                    st.session_state.search_results_df = results_df
                else:
                    st.info("No results found.")

        if not results_df.empty:
            st.divider()
            with st.container():
                st.subheader("Search Results")
                st.dataframe(results_df[['similarity', 'timestamp', 'host', 'message']], width='stretch', height=400)
            
            st.divider()
            with st.container():
                st.subheader("Cluster Analysis")
                if st.button("Cluster These Results"):
                    if len(results_df) < 5:
                        st.warning("Not enough results.")
                    else:
                        with st.spinner("Clustering with HDBSCAN..."):
                            clusterer = LogClusterer()
                            sub_msgs = results_df['message'].tolist()
                            sub_vecs = st.session_state.semantic_embedder.embed_logs(sub_msgs)
                            viz_df, labels = clusterer.cluster_and_visualize(sub_vecs, min_cluster_size=2)
                            
                            if not viz_df.empty:
                                viz_df['message'] = sub_msgs
                                c_plot, c_groups = st.columns([2, 1])
                                with c_plot:
                                    fig = px.scatter(viz_df, x='x', y='y', color='label', hover_data={'message': True}, title="Semantic Landscape")
                                    st.plotly_chart(fig, use_container_width=True)
                                with c_groups:
                                    st.write("**Discovered Groups:**")
                                    unique_labels = set(labels)
                                    for l in unique_labels:
                                        if str(l) == "-1": continue
                                        cluster_msgs = [m for m, lbl in zip(sub_msgs, labels) if lbl == l]
                                        label_text = clusterer.generate_label(cluster_msgs)
                                        st.info(f"**Group {l}:** {label_text}")

    def _render_settings_tab(self):
        st.markdown(f"## {get_icon_svg('settings', '#94a3b8')} System Settings", unsafe_allow_html=True)
        
        def mask_key(k):
             if k and len(k) > 4: return f"...{k[-4:]}"
             return "Not Set"

        st.subheader("API Keys")
        st.info("Keys are stored safely in session state (RAM).")
        
        with st.form("api_keys_form"):
            c1, c2 = st.columns(2)
            with c1:
                current_gemini = st.session_state.get('gemini_api_key', '')
                new_gemini = st.text_input("Google Gemini API Key (AI)", value=current_gemini, type="password")
            with c2:
                current_vt = st.session_state.get('vt_api_key', '')
                new_vt = st.text_input("VirusTotal API Key (IOC)", value=current_vt, type="password")
                
            c_save, c_clear = st.columns([1, 1])
            with c_save:
                submitted = st.form_submit_button("Save Configuration", type="primary")
            with c_clear:
                cleared = st.form_submit_button("Clear Keys", type="secondary")

            if cleared:
                st.session_state.gemini_api_key = ''
                st.session_state.vt_api_key = ''
                if HAS_AI: st.session_state.ai_gateway = None
                st.success("Keys Cleared.")
                st.rerun()
            
            if submitted:
                errors = []
                if new_gemini:
                    try:
                        import google.generativeai as genai
                        genai.configure(api_key=new_gemini)
                        model = genai.GenerativeModel('gemini-2.0-flash')
                        response = model.generate_content("test")
                        if not response: errors.append("Gemini Key: No response.")
                    except Exception as e:
                        errors.append(f"Gemini Key Error: {str(e)}")

                if new_vt:
                    try:
                        import requests
                        url = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
                        resp = requests.get(url, headers={"x-apikey": new_vt}, timeout=5)
                        if resp.status_code != 200: errors.append(f"VirusTotal Key: Status {resp.status_code}")
                    except Exception as e:
                        errors.append(f"VirusTotal Connection Failed: {str(e)}")

                if errors:
                    for err in errors: st.error(f"{err}")
                    st.warning("Configuration NOT saved.")
                else:
                    st.session_state.gemini_api_key = new_gemini
                    st.session_state.vt_api_key = new_vt
                    if HAS_AI: st.session_state.ai_gateway = AIGateway(api_key=new_gemini)
                    st.success("Configuration Verified & Saved!")
                    st.rerun()

        st.divider()
        st.subheader("System Status")
        s1, s2 = st.columns(2)
        with s1:
            st.write("**AI Subsystem**")
            k = st.session_state.get('gemini_api_key')
            if k:
                st.markdown(f"#### {get_icon_svg('connect', '#22d3ee')} Online", unsafe_allow_html=True)
                st.caption(f"Active Key: {mask_key(k)}")
            else:
                 st.markdown(f"#### {get_icon_svg('disconnect', '#ef4444')} Disconnected", unsafe_allow_html=True)
        with s2:
             st.write("**Threat Intel Subsystem**")
             k = st.session_state.get('vt_api_key')
             if k:
                 st.markdown(f"#### {get_icon_svg('connect', '#22d3ee')} Online", unsafe_allow_html=True)
                 st.caption(f"Active Key: {mask_key(k)}")
             else:
                 st.markdown(f"#### {get_icon_svg('disconnect', '#ef4444')} Disconnected", unsafe_allow_html=True)

if __name__ == "__main__":
    app_logic = StreamlitApp()
    app_logic.run()
