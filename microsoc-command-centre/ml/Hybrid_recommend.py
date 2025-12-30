def hybrid_remediation(attack_type, confidence=0.0, frequency=1):
    suggestions = {
        "sql_injection": "Apply input sanitization, WAF SQL filter, block for 30 min.",
        "xss_attempt": "Escape user output, enable CSP headers, audit input forms.",
        "directory_scan": "Throttle IP, serve fake honeypot paths for attacker deception.",
        "brute_force_login": "Enable MFA, account lockout policy, add invisible bot CAPTCHA.",
        "dos_flood": "Activate rate-limiter, drop packets, auto-scale system.",
        "threat_intel": "Auto blacklist for 24h, export IOC to SOC.",
        "sensitive_path_access": "Block, log, and alert — attempt to access system internals.",
        "ML_port_scan": "Block & deploy honeypot port response to observe attacker.",
        "ML_malware": "Quarantine connection, hash-check payload, inspect user session."
    }

    if confidence > 0.92:
        severity = "CRITICAL"
        action = "Immediate block & SOC notification"
    elif confidence > 0.80:
        severity = "HIGH"
        action = "Block temporarily & require validation"
    else:
        severity = "MEDIUM"
        action = "Monitor & log — suspicious but uncertain"

    base_suggestion = suggestions.get(attack_type.replace("ML_", ""), "Observe and analyze suspicious behavior")

    if frequency > 15:
        base_suggestion += " | Escalation: Multiple repeated attempts detected."

    return {
        "severity": severity,
        "suggestion": f"{base_suggestion}. Recommended action: {action}",
        "auto_action": "block" if severity in ["HIGH", "CRITICAL"] else "monitor"
    }
