import os
import re
import streamlit as st
import requests
import dns.resolver
import whois
from validators import email as validate_email
from urllib.parse import urlparse
from datetime import datetime

# --- Config ---
GROQ_API_KEY       = os.getenv("GROQ_API_KEY")       or st.secrets.get("GROQ_API_KEY", "")
GOOD_DOMAINS       = {"google.com", "microsoft.com", "github.com"}    # expand as needed
BLACKLISTED_DOMAINS= {"bad-domain.com", "malicious.org"}             # expand as needed

st.set_page_config(page_title="AI Phishing Detector", layout="centered")
st.title("📧 AI-Powered Phishing Detector & Responder")

# --- Inputs ---
sender_email = st.text_input("Sender Email Address:")
email_input  = st.text_area("Email / Message Content:", height=250)

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
    # MX lookup
    try:
        dns.resolver.resolve(domain, 'MX')
        st.success(f"✅ MX record found for `{domain}`")
    except Exception as e:
        st.error(f"❌ No MX record for `{domain}`: {e}")

    # Whitelist / Blacklist
    if domain in GOOD_DOMAINS:
        st.info(f"✅ Domain `{domain}` is in our **whitelist**.")
    if domain in BLACKLISTED_DOMAINS:
        st.error(f"⚠️ Domain `{domain}` is in our **blacklist**.")

    # --- Link Extraction & Heuristic Checks ---
    st.markdown("### 🌐 URL Heuristics")
    urls = set(re.findall(r'(https?://[^\s]+)', email_input))
    if not urls:
        st.info("🔍 No URLs detected in the message.")
    else:
        for url in urls:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()

            # 1) Reachability & HTTPS
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True)
                code = resp.status_code
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
                info = whois.whois(netloc)
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

    # --- Build Prompt & Call GROQ ---
    prompt = f"""
You are an AI cybersecurity assistant. Analyze the following email for phishing threats.

Sender: {sender_email}
Message:
\"\"\"{email_input}\"\"\"

Respond in this format:
1. Phishing Risk Level: (High / Medium / Low)
2. Reason: (Why you classified it so)
3. Recommended Action
4. Suggested Safe Response (if applicable)
"""
    st.markdown("### 🔍 AI Threat Analysis")
    with st.spinner("Calling GROQ API…"):
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "llama3-8b-8192",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst."},
                {"role": "user",   "content": prompt}
            ]
        }
        r = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=data)

    if r.status_code == 200:
        st.markdown(r.json()["choices"][0]["message"]["content"])
    else:
        st.error(f"Error {r.status_code}: {r.text}")
