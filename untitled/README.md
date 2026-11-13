# A Lightweight Cybersecurity Risk Scoring System for SMEs Using Threat Indicators

A complete, modular Python 3.11 cybersecurity risk scoring, indicator collection, SHA-256 deduplication, and counterfactual remediation prioritisation platform tailored for Small and Medium-sized Enterprises (SMEs).

---

## 1. System Workflow & Core Indicator Categories

**End-to-End Pipeline:**
`Indicator Collection` $\rightarrow$ `Data Normalisation` $\rightarrow$ `SHA-256 Deduplication` $\rightarrow$ `Dynamic Risk Scoring` $\rightarrow$ `Risk Classification` $\rightarrow$ `Remediation Prioritisation (RPI)` $\rightarrow$ `Interactive Dashboard`

**Four Cybersecurity Indicator Categories:**
1. **External Cyber Threat Intelligence** ($\lambda_k = 0.05\text{ day}^{-1}$ temporary exponential decay)
2. **Perimeter and Attack Surface Exposure** ($\lambda_k = 0.00$ persistent until remediated)
3. **Endpoint Configuration and Patch Indicators** ($\lambda_k = 0.00$ persistent until remediated)
4. **Identity and Authentication Hygiene** ($\lambda_k = 0.00$ persistent until remediated)

---

## 2. Exact Mathematical Specification

1. **Asset Criticality Weighting:**
   $$w_i = \frac{A_i}{\sum_{j=1}^{N} A_j}, \quad A_i \in \{1, 2, 3, 4, 5\}$$
2. **Temporal Decay:**
   $$D(t, t_0) = \exp\bigl(-\lambda_k \cdot (t - t_0)\bigr)$$
   * $\lambda_k = 0.05\text{ day}^{-1}$ for temporary threat intelligence indicators.
   * $\lambda_k = 0.00\text{ day}^{-1}$ for unresolved vulnerabilities, perimeter exposures, and missing MFA until remediation.
3. **Context Multiplier:**
   $$\Phi_{ik} = \Omega_{\text{KEV}}(k) \times \Psi_{\text{exp}}(i) \times \Gamma_{\text{ctrl}}(i, k)$$
   * $\Omega_{\text{KEV}}(k) = 1.8$ if in CISA KEV catalog; $1.5$ if $\text{EPSS} \ge 0.20$; otherwise $1.0$.
   * $\Psi_{\text{exp}}(i) = 1.4$ for internet-facing assets; $1.0$ for non-internet-facing assets.
   * $\Gamma_{\text{ctrl}}(i, k) \in [0.3, 1.0]$ compensating control factor.
4. **Effective Severity:**
   $$S(I_{ik}, t) = \min\Bigl(1.0,\; S_0(k) \cdot D(t, t_0) \cdot \Phi_{ik}\Bigr)$$
5. **Individual Asset Risk ($\beta = 0.5$):**
   $$R_i(t) = 100 \times \left[1 - \prod_{k \in K_i} \bigl(1 - C_{ik} \cdot S(I_{ik}, t)\bigr)\right] \times \left(\frac{A_i}{5}\right)^{0.5}$$
6. **Overall System Risk ($\alpha = 0.65$):**
   $$R_{\text{sys}} = 0.65 \cdot \max_i(R_i) + 0.35 \cdot \sum_{i=1}^{N} (w_i \cdot R_i)$$
7. **Remediation Priority Index ($\text{RPI}$):**
   $$\text{RPI}_{ik} = \left[\frac{R_i - R_i(-k)}{E_k}\right] \times \Omega_{\text{KEV}}(k)$$

---

## 3. Windows & Cross-Platform Installation and Execution

```powershell
# 1. Create and activate a Python 3.11 virtual environment (Windows PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Run deterministic CLI verification and 5 worked numerical examples
python main.py --verify

# 4. Run the automated unit & validation test suite
pytest -v
# Or using standard library unittest:
python -m unittest discover -s tests -v

# 5. Run the 150-asset / 1,000 & 10,000 indicator performance benchmark
python benchmark_performance.py

# 6. Launch the 8-page Streamlit dashboard
streamlit run main.py
```
