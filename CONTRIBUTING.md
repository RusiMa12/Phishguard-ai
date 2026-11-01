# Contributing to PhishGuard AI

First off, thank you for considering contributing to **PhishGuard AI**! It's people like you that make PhishGuard AI a comprehensive open-source cyber threat intelligence platform.

---

## 🛠️ Code of Conduct

By participating in this project, you agree to uphold a welcoming, respectful, and harassment-free environment for everyone.

---

## 🚀 How Can I Contribute?

### 1. Reporting Bugs
- Ensure the bug was not already reported by searching on GitHub under [Issues](../../issues).
- If you're unable to find an open issue addressing the problem, open a new one.
- Include a **clear title and description**, steps to reproduce the issue, and expected behavior.

### 2. Suggesting Enhancements
- Check the issue tracker to see if the feature has already been requested.
- Explain **why** this enhancement would be useful to cybersecurity analysts and developers.
- Provide pseudocode, API mockups, or heuristic rule logic if applicable.

### 3. Pull Requests (PRs)
1. Fork the repo and create your branch from `main`:
   ```bash
   git checkout -b feature/awesome-detection-rule
   ```
2. Follow clean code and Python PEP 8 conventions.
3. Test all changes:
   ```bash
   python backend/test_integration.py
   ```
4. Issue a pull request describing the changes and referencing any related issues.

---

## 🛡️ Security Guidelines

- **Never commit real malware samples, executables, or malicious payloads to the repository.**
- Never commit real API keys (VirusTotal, Telegram tokens, etc.). Use `.env.example` templates.
- All PE/APK parsing must strictly remain **in-memory** and **non-executable**.

Thank you for helping keep the digital space secure! 🔒
