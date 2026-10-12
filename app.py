"""
Phase 7: Web app - QR Code Phishing Detector
Run with:  streamlit run app.py
"""
import json
import os

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from qr_decoder import decode_qr_from_bytes
from risk_engine import LOG_PATH, assess, log_scan

st.set_page_config(page_title="QR Phishing Detector", page_icon="🛡️", layout="wide")

VERDICT_COLORS = {"Safe": "#1e9e5a", "Suspicious": "#e6a100", "Malicious": "#d63a3a"}
VERDICT_ICONS = {"Safe": "✅", "Suspicious": "⚠️", "Malicious": "⛔"}

# ---------- Sidebar ----------
with st.sidebar:
    st.title("🛡️ QR Phishing Detector")
    st.caption("Cyber Threat Intelligence & Analytics project")
    st.divider()
    use_intel = st.toggle("Use live threat intelligence", value=True,
                          help="VirusTotal, OpenPhish, WHOIS and redirect checks. "
                               "Turn off to run offline (rules + ML only).")
    scan_unknown = st.toggle("Submit unknown URLs to VirusTotal", value=False,
                             disabled=not use_intel,
                             help="Requests a fresh scan for URLs VirusTotal has never seen. "
                                  "Slower (about 30-45 seconds).")
    st.divider()
    st.markdown("**Detection layers**")
    st.markdown("1. Rule-based URL analysis  \n2. Threat intelligence feeds  \n"
                "3. Machine learning model")

tab_scan, tab_dash, tab_model = st.tabs(["🔍 Scan", "📊 Analytics Dashboard", "🧠 Model Performance"])


# ---------- Helpers ----------
def gauge(score, verdict):
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number={"suffix": "/100"},
        gauge={"axis": {"range": [0, 100]},
               "bar": {"color": VERDICT_COLORS[verdict]},
               "steps": [{"range": [0, 25], "color": "rgba(30,158,90,0.15)"},
                         {"range": [25, 50], "color": "rgba(230,161,0,0.15)"},
                         {"range": [50, 100], "color": "rgba(214,58,58,0.15)"}]}))
    fig.update_layout(height=250, margin=dict(l=35, r=35, t=30, b=10))
    return fig


def show_result(r):
    v = r["verdict"]
    st.markdown(
        f"<div style='padding:18px;border-radius:10px;background:{VERDICT_COLORS[v]};"
        f"color:white;font-size:28px;font-weight:700;text-align:center'>"
        f"{VERDICT_ICONS[v]} {v.upper()}</div>", unsafe_allow_html=True)
    if r["confirmed_by_intel"]:
        st.error("Confirmed by threat intelligence: this URL is a known Indicator of Compromise.")

    st.write("")
    c1, c2 = st.columns([1, 1.3])
    with c1:
        st.markdown("**Final risk score**")
        st.plotly_chart(gauge(r["final_score"], v), use_container_width=True)
    with c2:
        st.markdown("**Score from each detection layer**")
        ls = r["layer_scores"]
        layers = pd.DataFrame({
            "Layer": ["Rules", "Machine Learning", "Threat Intel"],
            "Score": [ls["rules"], ls["ml"], ls["intel"] if ls["intel"] is not None else 0],
        })
        fig = px.bar(layers, x="Score", y="Layer", orientation="h", range_x=[0, 100],
                     text="Score", color_discrete_sequence=["#3b6fd6"])
        fig.update_layout(height=230, margin=dict(l=10, r=10, t=10, b=10), yaxis_title=None)
        st.plotly_chart(fig, use_container_width=True)
        if ls["intel"] is None:
            st.caption("Threat intelligence was switched off for this scan.")

    st.markdown("**Why this verdict**")
    if r["reasons"]:
        for reason in r["reasons"]:
            st.markdown(f"- {reason}")
    else:
        st.markdown("- No red flags found by any layer.")

    if r["intel_sources"]:
        with st.expander("Threat intelligence details"):
            src = r["intel_sources"]
            vt = src["virustotal"]
            if vt.get("status") == "ok":
                st.markdown(f"**VirusTotal:** {vt['malicious']} malicious, {vt['suspicious']} suspicious, "
                            f"{vt['harmless']} harmless, {vt['undetected']} undetected")
            else:
                st.markdown(f"**VirusTotal:** {vt.get('status', '').replace('_', ' ')}")
            op = src["openphish"]
            st.markdown(f"**OpenPhish:** {'LISTED' if op.get('listed') else 'not listed'}"
                        + (f" (feed of {op['feed_size']:,} active phishing URLs)" if op.get("feed_size") else ""))
            w = src["whois"]
            st.markdown("**WHOIS:** " + (f"registered {w['created']} ({w['age_days']:,} days ago)"
                                          if w.get("status") == "ok" else w.get("status", "").replace("_", " ")))
            rd = src["redirects"]
            if rd.get("status") == "ok" and rd["hops"]:
                st.markdown("**Redirect chain:**")
                st.code("\n -> ".join(rd["chain"]), language=None)
            else:
                st.markdown(f"**Redirects:** {'none' if rd.get('status') == 'ok' else rd.get('status', '').replace('_', ' ')}")


def run_scan(url, source):
    with st.spinner("Analysing with all detection layers..."):
        result = assess(url, use_intel=use_intel, scan_if_unknown=scan_unknown)
    log_scan(result, source=source)
    st.markdown("**Decoded content** (shown as text only, never opened):")
    st.code(result["url"], language=None)
    show_result(result)


# ---------- Tab 1: Scan ----------
with tab_scan:
    st.header("Scan a QR code before you trust it")
    st.caption("The QR code is decoded and its link is inspected without ever visiting the page.")

    mode = st.radio("Input method", ["Upload image", "Use camera", "Paste URL"], horizontal=True)

    if mode == "Upload image":
        img = st.file_uploader("Upload a photo or screenshot of a QR code",
                               type=["png", "jpg", "jpeg", "webp", "bmp"])
        if img is not None:
            col_img, col_res = st.columns([1, 2.2])
            col_img.image(img, caption="Uploaded QR code", use_container_width=True)
            with col_res:
                try:
                    url = decode_qr_from_bytes(img.getvalue())
                    if url:
                        run_scan(url, "upload")
                    else:
                        st.warning("No QR code found in this image. Try a clearer or closer photo.")
                except ValueError as e:
                    st.error(str(e))

    elif mode == "Use camera":
        shot = st.camera_input("Point your camera at a QR code and take a picture")
        if shot is not None:
            url = decode_qr_from_bytes(shot.getvalue())
            if url:
                run_scan(url, "camera")
            else:
                st.warning("No QR code found. Hold the code closer and keep it steady.")

    else:
        typed = st.text_input("URL to check", placeholder="e.g. http://paypa1-secure-login.com/verify")
        if st.button("Analyse URL", type="primary") and typed.strip():
            run_scan(typed.strip(), "manual")


# ---------- Tab 2: Analytics dashboard ----------
with tab_dash:
    st.header("Threat analytics dashboard")
    if not os.path.exists(LOG_PATH):
        st.info("No scans yet. Scan a few QR codes and the analytics will appear here.")
    else:
        log = pd.read_csv(LOG_PATH, parse_dates=["timestamp"])
        total = len(log)
        counts = log["verdict"].value_counts()
        threats = counts.get("Malicious", 0) + counts.get("Suspicious", 0)

        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Total scans", total)
        k2.metric("Malicious", int(counts.get("Malicious", 0)))
        k3.metric("Suspicious", int(counts.get("Suspicious", 0)))
        k4.metric("Safe", int(counts.get("Safe", 0)))
        k5.metric("Threat rate", f"{threats / total:.0%}")

        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Verdict breakdown")
            vc = counts.reindex(["Safe", "Suspicious", "Malicious"]).fillna(0).reset_index()
            vc.columns = ["Verdict", "Count"]
            fig = px.pie(vc, names="Verdict", values="Count", hole=0.55,
                         color="Verdict", color_discrete_map=VERDICT_COLORS)
            fig.update_layout(height=320, margin=dict(t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            st.subheader("Scans over time")
            daily = (log.assign(date=log["timestamp"].dt.strftime("%d %b %Y"))
                     .groupby(["date", "verdict"]).size().reset_index(name="Scans"))
            fig = px.bar(daily, x="date", y="Scans", color="verdict",
                         color_discrete_map=VERDICT_COLORS)
            fig.update_layout(height=320, margin=dict(t=10, b=10), xaxis_title=None,
                              legend_title=None, xaxis_type="category")
            st.plotly_chart(fig, use_container_width=True)

        c3, c4 = st.columns(2)
        with c3:
            st.subheader("Top risky domains")
            risky = (log[log["verdict"] != "Safe"].groupby("domain")["final_score"]
                     .agg(["max", "count"]).sort_values("max", ascending=False).head(10)
                     .reset_index())
            risky.columns = ["Domain", "Highest score", "Times seen"]
            if risky.empty:
                st.caption("No risky domains detected yet.")
            else:
                st.dataframe(risky, hide_index=True, use_container_width=True)
        with c4:
            st.subheader("Most common threat indicators")
            reasons = (log[log["verdict"] != "Safe"]["top_reason"].dropna()
                       .value_counts().head(8).reset_index())
            reasons.columns = ["Indicator", "Count"]
            if reasons.empty:
                st.caption("No threat indicators recorded yet.")
            else:
                fig = px.bar(reasons, x="Count", y="Indicator", orientation="h",
                             color_discrete_sequence=["#d63a3a"])
                fig.update_layout(height=320, margin=dict(t=10, b=10), yaxis_title=None,
                                  yaxis={"categoryorder": "total ascending"})
                st.plotly_chart(fig, use_container_width=True)

        st.subheader("Average layer scores by verdict")
        avg = (log.groupby("verdict")[["rule_score", "ml_score", "intel_score"]].mean()
               .reindex(["Safe", "Suspicious", "Malicious"]).dropna(how="all").round(1))
        avg.columns = ["Rules", "Machine Learning", "Threat Intel"]
        st.dataframe(avg, use_container_width=True)

        st.subheader("Scan history")
        st.dataframe(log.sort_values("timestamp", ascending=False), hide_index=True,
                     use_container_width=True)
        st.download_button("Download scan log (CSV)", log.to_csv(index=False),
                           file_name="scan_log.csv", mime="text/csv")


# ---------- Tab 3: Model performance ----------
with tab_model:
    st.header("Machine learning model performance")
    metrics_path = os.path.join("models", "metrics.json")
    if not os.path.exists(metrics_path):
        st.info("Run `python train_model.py` first.")
    else:
        m = json.load(open(metrics_path))
        best = m["results"][m["best_model"]]
        st.markdown(f"**Selected model:** {m['best_model']}  |  trained on {m['train_size']:,} URLs, "
                    f"tested on {m['test_size']:,} unseen URLs (PhiUSIIL dataset)")
        a, b, c, d = st.columns(4)
        a.metric("Accuracy", f"{best['accuracy']:.1%}")
        b.metric("Precision", f"{best['precision']:.1%}")
        c.metric("Recall", f"{best['recall']:.1%}")
        d.metric("F1 score", f"{best['f1']:.1%}")

        table = pd.DataFrame(m["results"]).T[["accuracy", "precision", "recall", "f1"]]
        st.dataframe((table * 100).round(2).rename(columns=str.capitalize),
                     use_container_width=True)

        i1, i2 = st.columns(2)
        for col, name, title in [(i1, "confusion_matrix.png", "Confusion matrix"),
                                 (i2, "feature_importance.png", "Feature importance")]:
            path = os.path.join("models", name)
            if os.path.exists(path):
                col.image(path, caption=title, use_container_width=True)

        st.info("**Dataset bias correction.** In the PhiUSIIL dataset every legitimate URL is "
                "an https homepage (bias 1) and 97% start with 'www.' (bias 2). A model trained on "
                "full URLs learns these shortcuts instead of real phishing patterns, so this model "
                "uses registered-domain features only. Scheme, path and subdomain tricks are judged "
                "by the rule layer, and well-known domains are recognised by the reputation check.")

        for folder, title in [("evaluation", "Real-world evaluation (full system)"),
                              ("evaluation_heldout", "Held-out evaluation (fresh, never-seen phishing URLs)")]:
            eval_path = os.path.join(folder, "evaluation_metrics.json")
            if not os.path.exists(eval_path):
                continue
            st.subheader(title)
            ev = json.load(open(eval_path))
            ts = ev["test_set"]
            st.markdown(f"{ts['phishing']} live phishing URLs (OpenPhish, {ts['openphish_snapshot']}) "
                        f"+ {ts['legitimate']} legitimate URLs, each encoded as a QR code and decoded. "
                        f"QR decoding success: **{ev['qr_decode_success_rate']:.1%}**")
            et = pd.DataFrame(ev["methods"]).T
            et = (et[["accuracy", "precision", "recall", "f1", "false_positive_rate"]] * 100).round(1)
            et.columns = ["Accuracy", "Precision", "Recall", "F1", "False alarm rate"]
            st.dataframe(et, use_container_width=True)
            p = os.path.join(folder, "layer_comparison.png")
            if os.path.exists(p):
                st.image(p, use_container_width=True)
