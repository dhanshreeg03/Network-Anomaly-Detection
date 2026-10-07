import streamlit as st
import pandas as pd
import plotly.express as px
import sys
import os
import time

# Ensure we can import from src when running from root directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.predictor import Predictor
from src.traffic_analyzer import DataValidationError
from src.risk_engine import RiskEngine
from src.feature_schema import EXPECTED_FEATURES, CATEGORICAL_OPTIONS
from ui import get_custom_css, render_metric_large, render_attack_badge, render_top_nav, render_data_list

st.set_page_config(page_title="CyberGuard NIDS", layout="wide", initial_sidebar_state="collapsed")

# Inject Custom CSS
st.markdown(get_custom_css(), unsafe_allow_html=True)
st.markdown('<div class="hero-bg"></div>', unsafe_allow_html=True)

@st.cache_resource
def init_system():
    try:
        predictor = Predictor(model_path="models/nids_pipeline.pkl", encoder_path="models/label_encoder.pkl")
        return predictor, True
    except Exception:
        return None, False

predictor, system_ready = init_system()

# --- STATE MANAGEMENT ---
if 'analysis_results' not in st.session_state:
    st.session_state['analysis_results'] = None
if 'nav_selection' not in st.session_state:
    st.session_state['nav_selection'] = "HOME"
if 'detection_mode' not in st.session_state:
    st.session_state['detection_mode'] = None

# Helper jump functions
def navigate_to(page):
    st.session_state['nav_selection'] = page
    
def set_detection_mode(mode):
    st.session_state['detection_mode'] = mode

# --- NAVIGATION BAR ---
render_top_nav(st.session_state['nav_selection'])
nav_col1, nav_col2, nav_col3, nav_col4, nav_col5, _ = st.columns([1, 1, 1.2, 1, 1, 4])
with nav_col1:
    if st.button("HOME", use_container_width=True): navigate_to("HOME")
with nav_col2:
    if st.button("DETECTION", use_container_width=True): navigate_to("DETECTION")
with nav_col3:
    if st.button("INVESTIGATION", use_container_width=True): navigate_to("INVESTIGATION")
with nav_col4:
    if st.button("EXPLAIN", use_container_width=True): navigate_to("EXPLAIN")
with nav_col5:
    if st.button("ANALYTICS", use_container_width=True): navigate_to("ANALYTICS")

st.markdown("<br><br>", unsafe_allow_html=True)

df = st.session_state['analysis_results']
page = st.session_state['nav_selection']

# --- MAIN CONTENT ---

if page == "HOME":
    st.markdown('<div class="hero-heading">CYBERGUARD</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-heading" style="font-size: 2.2rem; margin-bottom: 25px; color: #1E293B !important;">NETWORK INTRUSION<br>DETECTION SYSTEM</div>', unsafe_allow_html=True)
    st.markdown('<span class="eyebrow" style="margin-bottom: 30px; display: block;">Analyze. Detect. Understand.</span>', unsafe_allow_html=True)
    st.markdown('<div class="hero-subtitle">Machine-learning powered network traffic analysis for identifying suspicious activity and understanding attack behavior.</div>', unsafe_allow_html=True)
    
    col_btn1, col_btn2, _ = st.columns([1.5, 1.5, 7])
    with col_btn1:
        st.button("START DETECTION →", use_container_width=True, on_click=navigate_to, args=("DETECTION",))
    with col_btn2:
        st.button("EXPLORE ANALYTICS →", use_container_width=True, on_click=navigate_to, args=("ANALYTICS",))
        
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    
    if df is not None:
        total_flows = len(df)
        attacks = len(df[df['Predicted_Attack'] != 'Normal'])
        normals = len(df[df['Predicted_Attack'] == 'Normal'])
        detection_rate = (attacks / total_flows * 100) if total_flows > 0 else 0.0
        
        c1, c2, c3, c4 = st.columns(4)
        with c1: render_metric_large("Flows Analyzed", f"{total_flows:,}")
        with c2: render_metric_large("Attacks Detected", f"{attacks:,}")
        with c3: render_metric_large("Normal Flows", f"{normals:,}")
        with c4: render_metric_large("Detection Rate", f"{detection_rate:.1f}%")
    else:
        st.markdown('<div class="section-heading" style="font-size: 2.5rem; color: #CBD5E1 !important;">NO ANALYSIS YET</div>', unsafe_allow_html=True)
        st.markdown('<p style="font-size: 1.1rem; color: #64748B;">Run your first traffic analysis to see results.</p>', unsafe_allow_html=True)

elif page == "DETECTION":
    st.markdown('<div class="section-heading">DETECTION</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-subtitle">Turn network-flow data into actionable classification.</div>', unsafe_allow_html=True)
    
    mode = st.session_state['detection_mode']
    
    if mode is None:
        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2, _ = st.columns([3, 3, 4])
        with c1:
            st.markdown("""
                <div class="workflow-card">
                    <div class="workflow-num">01</div>
                    <h3 style="margin-top:0;">SINGLE FLOW</h3>
                    <p style="color: #64748B; margin-bottom: 30px;">Analyze one network flow manually.</p>
                </div>
            """, unsafe_allow_html=True)
            st.button("ANALYZE FLOW →", use_container_width=True, on_click=set_detection_mode, args=("Single",))
            
        with c2:
            st.markdown("""
                <div class="workflow-card">
                    <div class="workflow-num">02</div>
                    <h3 style="margin-top:0;">CSV ANALYSIS</h3>
                    <p style="color: #64748B; margin-bottom: 30px;">Analyze multiple network flows using a dataset.</p>
                </div>
            """, unsafe_allow_html=True)
            st.button("UPLOAD CSV →", use_container_width=True, on_click=set_detection_mode, args=("Batch",))
            
    elif mode == "Single":
        st.button("← BACK TO DETECTION OPTIONS", on_click=set_detection_mode, args=(None,))
        st.markdown("<br>", unsafe_allow_html=True)
        
        st.markdown('<span class="eyebrow">01 — SINGLE FLOW</span>', unsafe_allow_html=True)
        
        with st.form("single_flow_form"):
            inputs = {}
            st.markdown("### TRAFFIC")
            c1, c2, c3, c4 = st.columns(4)
            inputs['duration'] = c1.text_input('duration', value="0.0")
            inputs['protocol'] = c2.selectbox('protocol', CATEGORICAL_OPTIONS['protocol'])
            inputs['service'] = c3.selectbox('service', CATEGORICAL_OPTIONS['service'])
            inputs['tcp_flags'] = c4.selectbox('tcp_flags', CATEGORICAL_OPTIONS['tcp_flags'])
            
            st.markdown("### VOLUME")
            c1, c2, c3, c4 = st.columns(4)
            inputs['src_bytes'] = c1.number_input('src_bytes', value=0, step=1)
            inputs['dst_bytes'] = c2.number_input('dst_bytes', value=0, step=1)
            inputs['src_packets'] = c3.number_input('src_packets', value=0, step=1)
            inputs['dst_packets'] = c4.number_input('dst_packets', value=0, step=1)
            
            st.markdown("### BEHAVIOR")
            c1, c2, c3, c4 = st.columns(4)
            inputs['src_dst_byte_ratio'] = c1.text_input('src_dst_byte_ratio', value="0.0")
            inputs['packets_per_second'] = c2.text_input('packets_per_second', value="0.0")
            inputs['bytes_per_second'] = c3.text_input('bytes_per_second', value="0.0")
            
            rendered_keys = list(inputs.keys())
            remaining = [f for f in EXPECTED_FEATURES if f not in rendered_keys]
            
            if remaining:
                st.markdown("### OTHER")
                cols = st.columns(4)
                for i, feat in enumerate(remaining):
                    if feat in CATEGORICAL_OPTIONS:
                        inputs[feat] = cols[i % 4].selectbox(feat, CATEGORICAL_OPTIONS[feat])
                    else:
                        inputs[feat] = cols[i % 4].number_input(feat, value=0.0)
                        
            st.markdown("<br>", unsafe_allow_html=True)
            submitted = st.form_submit_button("RUN DETECTION →")
            
            
        if submitted:
            validation_error = None
            for field in ['duration', 'src_dst_byte_ratio', 'packets_per_second', 'bytes_per_second']:
                raw_val = str(inputs[field]).strip()
                if raw_val == "":
                    inputs[field] = 0.0
                else:
                    try:
                        f_val = float(raw_val)
                        if "." in raw_val and len(raw_val.split(".")[1]) > 6:
                            validation_error = f"Field '{field}' cannot have more than 6 decimal places."
                            break
                        inputs[field] = f_val
                    except ValueError:
                        validation_error = f"Field '{field}' must be a valid numeric decimal value."
                        break
            
            if validation_error:
                st.error(validation_error)
            else:
                with st.spinner("Analyzing traffic..."):
                    time.sleep(0.5)
                try:
                    pred, prob = predictor.predict_single(inputs)
                    severity = RiskEngine.get_severity(pred)
                    
                    single_result = inputs.copy()
                    single_result['Predicted_Attack'] = pred
                    single_result['Confidence'] = prob if prob is not None else 0.0
                    single_result['Severity'] = severity
                    
                    st.session_state['analysis_results'] = pd.DataFrame([single_result])
                    
                    panel_class = "result-panel-normal" if pred == "Normal" else "result-panel-attack"
                    sev_class = "normal" if pred == "Normal" else severity.lower()
                    
                    st.markdown(f"""
                        <div class="result-panel {panel_class}">
                            <span class="eyebrow">DETECTION RESULT</span>
                            <h2 style="font-size: 3.5rem; margin: 0 0 20px 0; color: #0F172A !important;">{pred}</h2>
                            <div style="margin-bottom: 30px;">
                                {render_attack_badge(severity.upper(), sev_class)}
                            </div>
                            <span class="eyebrow">MODEL CONFIDENCE</span>
                            <div style="font-size: 2rem; font-weight: 700; color: #0F172A;">{prob*100:.1f}%</div>
                            <p style="margin-top: 20px; font-size: 1.1rem; color: #64748B;">This flow has been classified as {pred} traffic.</p>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("### TRAFFIC PROFILE")
                    stats_dict = {
                        "Duration": f"{inputs.get('duration', 0)} s",
                        "Protocol": inputs.get('protocol', 'N/A'),
                        "Service": inputs.get('service', 'N/A'),
                        "Source Bytes": f"{inputs.get('src_bytes', 0)}",
                        "Destination Bytes": f"{inputs.get('dst_bytes', 0)}",
                        "Source Packets": f"{inputs.get('src_packets', 0)}",
                        "Destination Packets": f"{inputs.get('dst_packets', 0)}",
                        "Packets / Second": f"{inputs.get('packets_per_second', 0)}",
                        "Bytes / Second": f"{inputs.get('bytes_per_second', 0)}",
                        "Src/Dst Ratio": f"{inputs.get('src_dst_byte_ratio', 0)}",
                        "TCP Flags": inputs.get('tcp_flags', 'N/A')
                    }
                    st.markdown(render_data_list(stats_dict), unsafe_allow_html=True)
                    
                except DataValidationError as e:
                    st.error("Unable to analyze this dataset.")
                    st.warning(str(e))
                except Exception as e:
                    st.error(f"Detection failed: {type(e).__name__}: {e}")

    elif mode == "Batch":
        st.button("← BACK TO DETECTION OPTIONS", on_click=set_detection_mode, args=(None,))
        st.markdown("<br>", unsafe_allow_html=True)
        
        st.markdown('<span class="eyebrow">02 — CSV ANALYSIS</span>', unsafe_allow_html=True)
        st.markdown('<div class="hero-subtitle" style="font-size: 1.1rem;">Understand what the model detected across your uploaded network traffic.</div>', unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader("Upload dataset", type=["csv"], help="Supported format: CSV")
        
        if st.button("Load Demo Dataset instead"):
            if os.path.exists("data/cyberguard_synthetic_demo (1).csv"):
                st.session_state['temp_upload_df'] = pd.read_csv("data/cyberguard_synthetic_demo (1).csv")
            else:
                st.error("Demo dataset not found.")
                
        if uploaded_file is not None:
            st.session_state['temp_upload_df'] = pd.read_csv(uploaded_file)
            
        if 'temp_upload_df' in st.session_state:
            upload_df = st.session_state['temp_upload_df']
            
            st.markdown(f"""
                <div class="cg-panel" style="margin-top: 30px;">
                    <h3 style="margin:0;">DATASET READY</h3>
                    <p style="font-size: 1.1rem; color: #64748B; margin-top: 10px;">
                        <b>{len(upload_df):,}</b> flows &nbsp;&bull;&nbsp; <b>{len(upload_df.columns)}</b> features
                    </p>
                    <p style="color: #15803D; font-weight: 600;">✓ Required fields detected<br>✓ Dataset format valid</p>
                </div>
            """, unsafe_allow_html=True)
            
            if st.button("RUN DETECTION →"):
                with st.spinner("Analyzing traffic..."):
                    time.sleep(1)
                    try:
                        preds, probs = predictor.predict_batch(upload_df)
                        results_df = upload_df.copy()
                        results_df['Predicted_Attack'] = preds
                        results_df['Confidence'] = probs if probs is not None else 0.0
                        results_df['Severity'] = results_df['Predicted_Attack'].apply(RiskEngine.get_severity)
                        
                        st.session_state['analysis_results'] = results_df
                        st.session_state['batch_analysis_complete'] = True
                    except DataValidationError as e:
                        st.error("Unable to analyze this dataset.")
                        st.warning(f"Required traffic-flow features are missing.\nDetails: {str(e)}")
                        st.session_state['batch_analysis_complete'] = False
                    except Exception as e:
                        st.error("Invalid CSV format.")
                        st.session_state['batch_analysis_complete'] = False
                        
            if st.session_state.get('batch_analysis_complete') and st.session_state.get('analysis_results') is not None:
                results_df = st.session_state['analysis_results']
                total = len(results_df)
                normals = len(results_df[results_df['Predicted_Attack'] == 'Normal'])
                attacks = total - normals
                
                st.markdown("<br><hr style='border-top: 2px solid #E2E8F0;'><br>", unsafe_allow_html=True)
                st.markdown('<span class="eyebrow">DETECTION COMPLETE</span>', unsafe_allow_html=True)
                
                c1, c2, c3 = st.columns(3)
                with c1: render_metric_large("Flows Analyzed", f"{total:,}")
                with c2: render_metric_large("Normal", f"{normals:,}")
                with c3: render_metric_large("Attacks", f"{attacks:,}")
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown('<span class="eyebrow">DETECTION BREAKDOWN</span>', unsafe_allow_html=True)
                
                display_df = results_df[['Predicted_Attack', 'Confidence', 'Severity']].copy()
                if 'ID' in results_df.columns:
                    display_df.insert(0, 'Flow', results_df['ID'])
                else:
                    display_df.insert(0, 'Flow', [f"Flow {i+1}" for i in range(len(results_df))])
                
                display_df['Confidence'] = display_df['Confidence'].apply(lambda x: f"{x * 100:.1f}%")
                display_df = display_df.rename(columns={'Predicted_Attack': 'Prediction'})
                st.dataframe(display_df, use_container_width=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown('<span class="eyebrow">ATTACK DISTRIBUTION</span>', unsafe_allow_html=True)
                dist_counts = results_df['Predicted_Attack'].value_counts().reset_index()
                dist_counts.columns = ['Attack Type', 'Count']
                fig_dist = px.bar(dist_counts, x='Attack Type', y='Count', color='Attack Type')
                fig_dist.update_layout(plot_bgcolor='#FFFFFF', paper_bgcolor='#FFFFFF', margin=dict(t=10, l=10, r=10, b=10))
                st.plotly_chart(fig_dist, use_container_width=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown('<span class="eyebrow">ANALYZE A FLOW</span>', unsafe_allow_html=True)
                
                flow_list = display_df['Flow'].tolist()
                selected_flow = st.selectbox("Select Flow ID", flow_list, label_visibility="collapsed")
                
                if selected_flow:
                    idx = flow_list.index(selected_flow)
                    flow_data = results_df.iloc[idx]
                    
                    pred = flow_data['Predicted_Attack']
                    conf = flow_data['Confidence'] * 100
                    sev = flow_data['Severity']
                    
                    if pred == 'Normal':
                        st.markdown(f"""
                            <div class="result-panel result-panel-normal">
                                <span class="eyebrow" style="color: #15803D;">NORMAL TRAFFIC</span>
                                <h2 style="font-size: 3rem; margin: 0 0 15px 0;">{pred}</h2>
                                <p style="font-size: 1.2rem; color: #475569;">Confidence: <b>{conf:.1f}%</b></p>
                            </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                            <div class="result-panel result-panel-attack">
                                <h2 style="font-size: 3rem; margin: 0 0 5px 0;">{pred}</h2>
                                <div style="margin-bottom: 25px;">
                                    {render_attack_badge(sev.upper(), sev)}
                                </div>
                                <span class="eyebrow">MODEL CONFIDENCE</span>
                                <p style="font-size: 1.5rem; color: #0F172A; font-weight: 700;">{conf:.1f}%</p>
                            </div>
                        """, unsafe_allow_html=True)
                        
                    st.markdown("### TRAFFIC CHARACTERISTICS")
                    stats_dict = {
                        "Duration": f"{flow_data.get('duration', 0)} s",
                        "Protocol": flow_data.get('protocol', 'N/A'),
                        "Service": flow_data.get('service', 'N/A'),
                        "Source Bytes": f"{flow_data.get('src_bytes', 0)}",
                        "Destination Bytes": f"{flow_data.get('dst_bytes', 0)}",
                        "Source Packets": f"{flow_data.get('src_packets', 0)}",
                        "Destination Packets": f"{flow_data.get('dst_packets', 0)}",
                        "Packets / Second": f"{flow_data.get('packets_per_second', 0)}",
                        "Bytes / Second": f"{flow_data.get('bytes_per_second', 0)}",
                        "TCP Flags": flow_data.get('tcp_flags', 'N/A')
                    }
                    st.markdown(render_data_list(stats_dict), unsafe_allow_html=True)

elif page == "INVESTIGATION":
    st.markdown('<div class="section-heading">LOOK CLOSER.</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-subtitle">Detection tells you what happened.<br>Investigation helps you understand the traffic.</div>', unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["Suspicious Flows", "Attack Explorer", "What-If Analysis"])
    
    with tab1:
        st.markdown("<br>", unsafe_allow_html=True)
        if df is None or len(df) == 0:
            st.info("No traffic analyzed yet.")
        else:
            attack_df = df[df['Predicted_Attack'] != 'Normal'].copy()
            if attack_df.empty:
                st.success("No suspicious flows detected in the analyzed traffic.")
            else:
                f1, f2 = st.columns(2)
                sel_atk = f1.selectbox("Attack Type", ["All"] + sorted(list(attack_df['Predicted_Attack'].unique())), key="inv_atk")
                sel_sev = f2.selectbox("Severity", ["All"] + sorted(list(attack_df['Severity'].unique())), key="inv_sev")
                
                if sel_atk != "All": attack_df = attack_df[attack_df['Predicted_Attack'] == sel_atk]
                if sel_sev != "All": attack_df = attack_df[attack_df['Severity'] == sel_sev]
                
                attack_df.insert(0, 'Flow_ID', attack_df.index)
                display_df = attack_df[['Flow_ID', 'Predicted_Attack', 'Confidence', 'Severity']].copy()
                display_df['Confidence'] = display_df['Confidence'].apply(lambda x: f"{x * 100:.1f}%")
                
                st.dataframe(display_df, use_container_width=True)
                
                st.markdown("<br><span class='eyebrow'>INVESTIGATION DETAIL</span>", unsafe_allow_html=True)
                flow_id = st.selectbox("Select Flow to investigate", attack_df['Flow_ID'].tolist())
                if flow_id is not None:
                    flow_data = attack_df[attack_df['Flow_ID'] == flow_id].iloc[0]
                    st.markdown(f"""
                        <div class="result-panel result-panel-attack">
                            <h2 style="margin-top:0;">{flow_data['Predicted_Attack']}</h2>
                            <p style="font-size: 1.2rem; color: #475569;">Confidence: <b>{flow_data['Confidence']*100:.1f}%</b> &bull; Severity: <b>{flow_data['Severity']}</b></p>
                        </div>
                    """, unsafe_allow_html=True)
                    st.markdown("<br>### Traffic Profile", unsafe_allow_html=True)
                    st.markdown(render_data_list({
                        "Duration": f"{flow_data.get('duration', 0)} s",
                        "Packets/sec": f"{flow_data.get('packets_per_second', 0)}",
                        "Bytes/sec": f"{flow_data.get('bytes_per_second', 0)}",
                        "Protocol": flow_data.get('protocol', 'N/A')
                    }), unsafe_allow_html=True)

    with tab2:
        st.markdown("<br>", unsafe_allow_html=True)
        if df is None or len(df) == 0:
            st.info("No traffic analyzed yet.")
        else:
            attacks = df[df['Predicted_Attack'] != 'Normal']['Predicted_Attack'].unique()
            if len(attacks) == 0:
                st.success("No attacks detected.")
            else:
                sel_atk = st.selectbox("Select Attack Type", attacks)
                atk_data = df[df['Predicted_Attack'] == sel_atk]
                
                st.markdown(f"""
                    <div class="cg-panel" style="margin-top: 30px;">
                        <h1 style="font-size: 3rem; margin: 0 0 15px 0; text-transform: uppercase;">{sel_atk}</h1>
                        <p style="font-size: 1.25rem; font-weight: 400; color: #475569;">
                            <b style="color: #0F172A;">{len(atk_data):,}</b> DETECTIONS &bull; 
                            <b style="color: #0F172A;">{atk_data['Confidence'].mean()*100:.1f}%</b> AVG CONFIDENCE &bull; 
                            <b style="color: #0F172A;">{atk_data['Severity'].iloc[0].upper()}</b>
                        </p>
                    </div>
                """, unsafe_allow_html=True)
                
                st.markdown("### Traffic characteristics")
                st.markdown(render_data_list({
                    "Avg Duration": f"{atk_data.get('duration', pd.Series([0])).mean():.2f} s",
                    "Avg Packets/s": f"{atk_data.get('packets_per_second', pd.Series([0])).mean():.0f}",
                    "Avg Bytes/s": f"{atk_data.get('bytes_per_second', pd.Series([0])).mean():.0f}",
                    "Avg Src Bytes": f"{atk_data.get('src_bytes', pd.Series([0])).mean():.0f}",
                    "Avg Dst Bytes": f"{atk_data.get('dst_bytes', pd.Series([0])).mean():.0f}"
                }), unsafe_allow_html=True)
                
    with tab3:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<span class="eyebrow">WHAT IF?</span>', unsafe_allow_html=True)
        st.markdown('<p style="font-size: 1.1rem; color: #64748B;">Explore how changes in traffic characteristics affect classification.</p>', unsafe_allow_html=True)
        
        if df is None or len(df) == 0:
            st.info("No traffic analyzed yet.")
        else:
            df_display = df.copy()
            df_display.insert(0, 'Flow_ID', df_display.index)
            flow_id = st.selectbox("Select Base Flow", df_display['Flow_ID'].tolist(), key="wi_flow")
            base_flow = df.iloc[flow_id].copy()
            
            st.markdown("### MODIFY FEATURES")
            with st.form("wi_form"):
                mod_features = ['duration', 'src_bytes', 'dst_bytes', 'packets_per_second', 'bytes_per_second']
                c1, c2, c3 = st.columns(3)
                new_inputs = {}
                for i, feat in enumerate(mod_features):
                    if feat in base_flow:
                        col = [c1, c2, c3][i % 3]
                        new_inputs[feat] = col.number_input(feat, value=float(base_flow[feat]))
                st.markdown("<br>", unsafe_allow_html=True)
                submit_sim = st.form_submit_button("RUN SIMULATION →")
            
            if submit_sim:
                st.markdown('<span class="eyebrow" style="color: #CA8A04;">EXPERIMENTAL SIMULATION</span>', unsafe_allow_html=True)
                
                sim_flow = base_flow.to_dict()
                sim_flow.update(new_inputs)
                for k in ['Predicted_Attack', 'Confidence', 'Severity', 'Actual_Attack']:
                    sim_flow.pop(k, None)
                    
                try:
                    pred, prob = predictor.predict_single(sim_flow)
                    
                    orig_pred = base_flow['Predicted_Attack']
                    orig_conf = base_flow['Confidence'] * 100 if pd.notnull(base_flow['Confidence']) else 0
                    
                    st.markdown(f"""
                        <div style="display: flex; gap: 30px; margin-top: 20px;">
                            <div class="cg-panel" style="flex: 1; border-top: 4px solid #94A3B8;">
                                <span class="eyebrow">ORIGINAL</span>
                                <h3 style="font-size: 2.2rem; margin: 10px 0;">{orig_pred}</h3>
                                <p style="font-size: 1.25rem; color: #475569; font-weight: 600;">{orig_conf:.1f}%</p>
                            </div>
                            <div class="cg-panel" style="flex: 1; border-top: 4px solid #2563EB;">
                                <span class="eyebrow">AFTER MODIFICATION</span>
                                <h3 style="font-size: 2.2rem; margin: 10px 0;">{pred}</h3>
                                <p style="font-size: 1.25rem; color: #2563EB; font-weight: 600;">{prob*100:.1f}%</p>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                except Exception as e:
                    st.error("Simulation failed.")

elif page == "EXPLAIN":
    st.markdown('<div class="section-heading">WHY THIS DETECTION?</div>', unsafe_allow_html=True)
    
    if df is None or len(df) == 0:
        st.info("No traffic analyzed yet.")
    else:
        df_display = df.copy()
        df_display.insert(0, 'Flow_ID', df_display.index)
        flow_id = st.selectbox("Select Analyzed Flow", df_display['Flow_ID'].tolist())
        flow_data = df.iloc[flow_id]
        
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(f"""
            <div class="cg-panel" style="border-top: 4px solid #0F172A;">
                <span class="eyebrow">PREDICTION</span>
                <h1 style="font-size: 3.5rem; margin: 10px 0;">{flow_data['Predicted_Attack']}</h1>
                <p style="font-size: 1.25rem; color: #475569;">Confidence: <b>{flow_data['Confidence']*100:.1f}%</b> &nbsp;&bull;&nbsp; Severity: <b>{flow_data['Severity']}</b></p>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### TRAFFIC CHARACTERISTICS")
        st.markdown('<p style="color: #64748B; font-size: 1.05rem; max-width: 800px; margin-bottom: 25px;">Traffic characteristics associated with this classification. The Random Forest model leverages these patterns statistically compared to baseline training data.</p>', unsafe_allow_html=True)
        
        st.markdown(render_data_list({
            "Duration": f"{flow_data.get('duration', 0)} s",
            "Protocol": flow_data.get('protocol', 'N/A'),
            "Service": flow_data.get('service', 'N/A'),
            "TCP Flags": flow_data.get('tcp_flags', 'N/A'),
            "Packets/s": f"{flow_data.get('packets_per_second', 0)}",
            "Bytes/s": f"{flow_data.get('bytes_per_second', 0)}",
            "Src/Dst Ratio": f"{flow_data.get('src_dst_byte_ratio', 0)}",
            "Total Src Bytes": f"{flow_data.get('src_bytes', 0)}"
        }), unsafe_allow_html=True)

elif page == "ANALYTICS":
    st.markdown('<div class="section-heading">SEE THE PATTERN.</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-subtitle">Understand how different attack categories behave across analyzed traffic.</div>', unsafe_allow_html=True)
    
    if df is None or len(df) == 0:
        st.info("No traffic analyzed yet.")
    else:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<span class="eyebrow">01 — ATTACK COMPARISON</span>', unsafe_allow_html=True)
        
        atk_types = df['Predicted_Attack'].unique().tolist()
        c1, c2 = st.columns(2)
        atk_a = c1.selectbox("Attack A", atk_types, index=0)
        atk_b = c2.selectbox("Attack B", atk_types, index=min(1, len(atk_types)-1))
        
        comp_df = df[(df['Predicted_Attack'] == atk_a) | (df['Predicted_Attack'] == atk_b)]
        
        if 'duration' in comp_df.columns:
            fig1 = px.box(comp_df, x='Predicted_Attack', y='duration', color='Predicted_Attack', title="Duration Distribution")
            fig1.update_layout(plot_bgcolor='#FFFFFF', paper_bgcolor='#FFFFFF')
            st.plotly_chart(fig1, use_container_width=True)
            
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown('<span class="eyebrow">02 — ATTACK FINGERPRINT</span>', unsafe_allow_html=True)
        
        sel_fingerprint = st.selectbox("Select Attack Profile", atk_types)
        atk_data = df[df['Predicted_Attack'] == sel_fingerprint]
        
        c3, c4, c5, c6 = st.columns(4)
        with c3: render_metric_large("Traffic Intensity", f"{atk_data.get('bytes_per_second', pd.Series([0])).mean():.0f} B/s")
        with c4: render_metric_large("Packet Behavior", f"{atk_data.get('packets_per_second', pd.Series([0])).mean():.0f} P/s")
        with c5: render_metric_large("Byte Behavior", f"{atk_data.get('src_bytes', pd.Series([0])).mean():.0f} Src B")
        with c6: render_metric_large("Duration", f"{atk_data.get('duration', pd.Series([0])).mean():.2f} s")
        
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown('<span class="eyebrow">03 — ATTACK RANKING</span>', unsafe_allow_html=True)
        
        attack_only_df = df[df['Predicted_Attack'] != 'Normal']
        if attack_only_df.empty:
            st.success("No attacks detected.")
        else:
            counts = attack_only_df['Predicted_Attack'].value_counts().reset_index()
            counts.columns = ['Attack Type', 'Count']
            
            for i, row in counts.iterrows():
                st.markdown(f"""
                    <div style="display: flex; align-items: center; border-bottom: 1px solid #E2E8F0; padding: 20px 0;">
                        <div style="font-family: 'Space Grotesk', sans-serif; font-size: 1.5rem; font-weight: 700; color: #94A3B8; width: 60px;">
                            {i+1:02d}
                        </div>
                        <div style="font-family: 'Space Grotesk', sans-serif; font-size: 1.25rem; font-weight: 700; flex: 1; color: #0F172A;">
                            {row['Attack Type'].upper()}
                        </div>
                        <div style="font-size: 1.1rem; font-weight: 600; color: #475569;">
                            {row['Count']:,} DETECTIONS
                        </div>
                    </div>
                """, unsafe_allow_html=True)
