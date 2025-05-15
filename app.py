# app.py

import os
import re
import streamlit as st
import requests
import dns.resolver
import whois
from validators import email as validate_email
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup

# --- Config ---
GROQ_API_KEY        = os.getenv("GROQ_API_KEY")       or st.secrets.get("GROQ_API_KEY", "")
GOOD_DOMAINS        = {"google.com", "microsoft.com", "github.com"}
BLACKLISTED_DOMAINS = {"bad-domain.com", "malicious.org"}
MAX_CHUNK_SIZE      = 2000  # chars per chunk to stay under token limits

st.set_page_config(page_title="AI Phishing Detector", layout="centered")
st.title("📧 AI-Powered Phishing Detector & Responder")

# --- Inputs ---
sender_email = st.text_input("Sender Email Address:")
email_input  = st.text_area(
    "Email / Message Content (plain‑text or HTML):",
    height=250
)

# Show a preview so HTML links stay clickable
if email_input:
    st.markdown("### 📨 Preview of Pasted Content", unsafe_allow_html=True)
    st.markdown(email_input, unsafe_allow_html=True)

if st.button("Analyze for Phishing"):
    # --- Basic Validation ---
    if not GROQ_API_KEY:
        st.error("🔑 Missing GROQ_API_KEY; set it in env or Streamlit secrets.")
        st.stop()
    if not validate_email(sender_email or ""):
        st.error("❌ Please enter a valid sender email address.")
        st.stop()
    if not email_input.strip():
        st.warning("✉️ Paste the email content to analyze.")
        st.stop()

    # --- Sender Domain Checks ---
    domain = sender_email.split("@")[-1].lower()
    st.markdown("### 📨 Sender Domain Verification")
    try:
        dns.resolver.resolve(domain, 'MX')
        st.success(f"✅ MX record found for `{domain}`")
    except Exception as e:
        st.error(f"❌ No MX record for `{domain}`: {e}")

    if domain in GOOD_DOMAINS:
        st.info(f"✅ Domain `{domain}` is whitelisted.")
    if domain in BLACKLISTED_DOMAINS:
        st.error(f"⚠️ Domain `{domain}` is blacklisted.")

    # --- URL Extraction & Heuristics ---
    st.markdown("### 🌐 URL Heuristics")
    # plain-text URLs
    plain_urls = set(re.findall(r'(https?://[^\s]+)', email_input))
    # HTML links
    soup     = BeautifulSoup(email_input, "html.parser")
    html_urls = {a["href"] for a in soup.find_all("a", href=True)}
    urls      = plain_urls | html_urls

    if not urls:
        st.info("🔍 No URLs detected in the message.")
    else:
        for url in urls:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()

            # 1) Reachability & HTTPS
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True)
                code  = resp.status_code
                proto = parsed.scheme.upper()
                if code < 400 and proto == "HTTPS":
                    st.success(f"🟢 {url} → reachable ({code}), uses HTTPS")
                elif code < 400:
                    st.warning(f"🟡 {url} → reachable ({code}), but not HTTPS")
                else:
                    st.error(f"🔴 {url} → HTTP {code}")
            except Exception as e:
                st.error(f"❌ {url} → not reachable: {e}")

            # 2) Domain Age via WHOIS
            try:
                info     = whois.whois(netloc)
                creation = info.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                if creation:
                    age_days = (datetime.utcnow() - creation).days
                    if age_days < 30:
                        st.warning(f"⚠️ `{netloc}` registered {age_days} days ago (new domain)")
                    else:
                        st.info(f"✅ `{netloc}` age: {age_days:,} days")
                else:
                    st.info(f"ℹ️ No creation date for `{netloc}`")
            except Exception as e:
                st.warning(f"❔ WHOIS lookup failed for `{netloc}`: {e}")

    # --- Chunk the Message Body ---
    chunks = [
        email_input[i : i + MAX_CHUNK_SIZE]
        for i in range(0, len(email_input), MAX_CHUNK_SIZE)
    ]

    # --- Analyze Each Chunk for Suspicious Indicators ---
    chunk_analyses = []
    for idx, chunk in enumerate(chunks, start=1):
        prompt_chunk = (
            f"You are a cybersecurity analyst. Here is part {idx}/{len(chunks)} of an email:\n\n"
            f"\"\"\"{chunk}\"\"\"\n\n"
            "List any phishing indicators or suspicious elements found."
        )
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "llama3-8b-8192",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst."},
                {"role": "user",   "content": prompt_chunk}
            ]
        }
        with st.spinner(f"Analyzing chunk {idx}/{len(chunks)}…"):
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers, json=data, timeout=60
            )
        if resp.status_code == 200:
            analysis = resp.json()["choices"][0]["message"]["content"]
            chunk_analyses.append(f"#### Chunk {idx} Findings\n{analysis}")
        else:
            chunk_analyses.append(f"#### Chunk {idx} Error: HTTP {resp.status_code}")

    # --- Final Consolidation Prompt ---
    full_analysis = "\n\n".join(chunk_analyses)
    final_prompt = (
        "You are an AI cybersecurity assistant. Based on the following per‑chunk analyses:\n\n"
        f"{full_analysis}\n\n"
        "Provide:\n"
        "1. Overall Phishing Risk Level (High / Medium / Low)\n"
        "2. Consolidated Reasoning\n"
        "3. Recommended Action\n"
        "4. Suggested Safe Response\n"
        "5. Final Conclusion Summary"
    )
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "llama3-8b-8192",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity analyst."},
            {"role": "user",   "content": final_prompt}
        ]
    }

    st.markdown("### 🔍 AI Final Threat Analysis")
    with st.spinner("Generating final summary…"):
        final_resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers, json=data, timeout=60
        )
    if final_resp.status_code == 200:
        st.markdown(final_resp.json()["choices"][0]["message"]["content"])
    else:
        st.error(f"Error {final_resp.status_code}: {final_resp.text}")
