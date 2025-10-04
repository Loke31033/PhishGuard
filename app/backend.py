import dns.resolver
import dkim
import spf
import re

def check_spf(domain, ip, sender):
    """Check SPF record for domain"""
    try:
        result, explanation = spf.check2(i=ip, s=sender, h=domain)
        return result  # 'pass', 'fail', 'neutral', etc.
    except Exception as e:
        return f"error: {str(e)}"

def check_dkim(raw_email):
    """Check DKIM signature"""
    try:
        if dkim.verify(raw_email.encode()):
            return "pass"
        else:
            return "fail"
    except Exception as e:
        return f"error: {str(e)}"

def check_dmarc(domain):
    """Check DMARC record for domain"""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith("v=dmarc1"):
                if "p=none" in txt.lower():
                    return "none"
                elif "p=quarantine" in txt.lower():
                    return "quarantine"
                elif "p=reject" in txt.lower():
                    return "pass"  # treated as protection in place
        return "fail"
    except Exception:
        return "none"

def extract_domain_from_email(email):
    match = re.search(r'@([\w\.-]+)', email)
    if match:
        return match.group(1)
    return ""

def check_email_auth(email_raw, sender_ip="8.8.8.8"):
    """
    Input:
        email_raw: raw email text (.eml)
        sender_ip: IP of sending server (optional)
    Returns:
        dict with SPF, DKIM, DMARC results
    """
    # Extract From address
    from_match = re.search(r'^From:\s*(.*)', email_raw, re.MULTILINE | re.IGNORECASE)
    from_addr = from_match.group(1).strip() if from_match else ""
    domain = extract_domain_from_email(from_addr)

    spf_result = check_spf(domain, sender_ip, from_addr)
    dkim_result = check_dkim(email_raw)
    dmarc_result = check_dmarc(domain)

    return {
        "from": from_addr,
        "domain": domain,
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result
    }

