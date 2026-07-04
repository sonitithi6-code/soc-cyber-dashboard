import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="SOC Cyber Threat Dashboard", layout="wide")

# Auto-refresh the whole app every 2 minutes so the page picks up new data
# without the visitor needing to hit reload.
st_autorefresh(interval=2 * 60 * 1000, key="dashboard_autorefresh")

st.title("🛡️ Smart Cyber Threat Monitoring System")
st.markdown("Real-time telemetry analysis and risk vector scoring panel.")


def fetch_data():
    try:
        conn = sqlite3.connect("cyber_security.db")
        df = pd.read_sql_query("SELECT * FROM threats ORDER BY id DESC", conn)
        conn.close()
        df['severity'] = pd.to_numeric(df['severity'])
        return df
    except Exception:
        return pd.DataFrame(columns=['id', 'timestamp', 'threat_type', 'description', 'severity'])


df = fetch_data()

st.caption(f"Last checked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · auto-refreshes every 2 minutes")

# 2. Metric Calculations
total_events = len(df)
high_risk_events = len(df[df['severity'] >= 7]) if total_events > 0 else 0

col1, col2 = st.columns(2)
col1.metric("Total Monitored Events", total_events)
col2.metric("Critical Alerts Caught", high_risk_events)

# 3. Charts Section
chart_col, table_col = st.columns([2, 1])

with chart_col:
    st.subheader("Threat Activity over Time")
    if not df.empty:
        plot_df = df.copy()
        plot_df['timestamp'] = pd.to_datetime(plot_df['timestamp'], format='mixed')
        fig = px.scatter(plot_df, x='timestamp', y='severity', color='threat_type')
        fig.update_xaxes(type='date')
        st.plotly_chart(fig, use_container_width=True, key="threat_activity_chart")
    else:
        st.info("Awaiting raw collection streams...")

with table_col:
    st.subheader("Event Distribution")
    if not df.empty:
        pie_fig = px.pie(df, names='threat_type', hole=0.4)
        st.plotly_chart(pie_fig, use_container_width=True, key="threat_pie_chart")

# 4. Logs Feed Table
st.subheader("📋 Critical Event Feed Logs")
if not df.empty:
    st.dataframe(df[['timestamp', 'threat_type', 'severity', 'description']], use_container_width=True)
else:
    st.write("No logs available yet.")
