def determine_severity(reason: str, score: int) -> str:
    """
    Menentukan severity berdasarkan kategori OWASP & skor risiko.

    Parameters
    ----------
    reason : str
        Alasan / kategori yang memicu tindakan keamanan (mis. 'xss', 'tls_invalid', 'geo_block')
    score : int
        Skor risiko numerik (0–100) hasil dari calculate_risk_score()

    Returns
    -------
    str
        Salah satu dari: "low", "medium", "high", atau "critical"
    """
    reason = (reason or "").lower()

    # === Berdasarkan kategori OWASP Top 10 ===
    if any(x in reason for x in ["sql", "xss", "injection", "ssrf", "csrf"]):
        return "critical"
    if any(x in reason for x in ["tls", "signature", "hmac", "encryption"]):
        return "high"
    if any(x in reason for x in ["reputation", "asn", "iprep", "botnet"]):
        return "high"
    if any(x in reason for x in ["schema", "format", "json", "anomaly"]):
        return "medium"
    if any(x in reason for x in ["missing", "invalid", "unauthorized", "access"]):
        return "medium"
    if any(x in reason for x in ["geo", "country", "block"]):
        return "critical"

    # === Berdasarkan skor risiko numerik ===
    if score >= 80:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 30:
        return "medium"
    return "low"
