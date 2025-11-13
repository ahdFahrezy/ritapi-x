# utils/ip_reputation.py

import logging

logger = logging.getLogger(__name__)

# Threat sources yang otomatis kita anggap berbahaya
THREAT_SOURCES = {"TOR", "EMERGING_THREATS", "FIREHOL"}
# Override sources dari internal admin/operator
OVERRIDE_SOURCES = {"INTERNAL_ALLOW", "INTERNAL_DENY"}

def handle_ip_reputation(client_ip, rep_module=None, alert_module=None, block_module=None, service_id=None):
    """
    Jalankan IP reputation check, return (score, blocked, reason).
    Jika IP flagged (e.g. INTERNAL_DENY, TOR/FIREHOL), langsung block dan alert.
    """

    try:
        if not rep_module:
            logger.debug("No IP reputation module configured")
            return 0, False, None

        # Panggil modul reputasi IP (biasanya IpReputationService.check_reputation)
        rep = rep_module(client_ip, service_id=service_id) 
        score = rep.reputation_score

        sources = rep.scores.get("sources", []) if isinstance(rep.scores, dict) else []
        sources_lower = set(s.upper() for s in sources)

        # === 1. Block if matched INTERNAL_DENY ===
        if "INTERNAL_DENY" in sources_lower:
            reason = "IP_BLACKLISTED"
            detail = "Blocked by internal deny list"

            if block_module:
                try:
                    block_module.block_ip(client_ip, reason=reason, severity="critical")
                except Exception:
                    logger.warning(f"[IPREP] Failed to block {client_ip} via block_module")

            if alert_module:
                try:
                    alert_module.create_alert("BLOCKED", client_ip, detail, "critical")
                except Exception:
                    logger.warning(f"[IPREP] Failed to alert for {client_ip}")

            return score, True, reason

        # === 2. Allow if matched INTERNAL_ALLOW ===
        if "INTERNAL_ALLOW" in sources_lower:
            # Skip block, even if reputation score is low
            logger.info(f"[IPREP] {client_ip} allowed via internal allow list")
            return score, False, None

        # === 3. Block if matched known threat feeds ===
        flagged = rep.is_tor or bool(THREAT_SOURCES & sources_lower)
        if flagged:
            reason = f"iprep_flagged:{','.join(sources)}"
            detail = f"Blocked by IP reputation ({sources})"

            if block_module:
                try:
                    block_module.block_ip(client_ip, reason=reason, severity="high")
                except Exception:
                    logger.warning(f"[IPREP] Failed to block {client_ip}")

            if alert_module:
                try:
                    alert_module.create_alert("BLOCKED", client_ip, detail, "high")
                except Exception:
                    logger.warning(f"[IPREP] Failed to alert for {client_ip}")

            return score, True, reason

        # === 4. Clean IP ===
        return score, False, None

    except Exception as e:
        logger.warning(f"[IPREP] Error checking IP {client_ip}: {e}")
        return 0, False, None
