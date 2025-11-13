import logging

logger = logging.getLogger(__name__)

def calculate_risk_score(asn_score, iprep_score, json_valid=True, tls_valid=True):
    """
    Hitung skor risiko gabungan berdasarkan faktor keamanan.
    """
    score = float(asn_score) + float(iprep_score)

    if not json_valid:
        score -= 5
    if not tls_valid:
        score -= 1
        
    return score


def decide_action(score, ALREADY_BLOCKED=False, block_threshold=-4.0):
    """
    Tentukan keputusan akhir berdasarkan skor dan status blok.
    Return tuple: (decision, reason)
    """
    if ALREADY_BLOCKED:
        return "block", "ALREADY_BLOCKED"
    if score < block_threshold:
        return "block", "score_too_low"
    return "allow", "ok"
