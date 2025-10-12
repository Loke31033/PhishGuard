import dns.resolver
import dns.exception
import re
from typing import Dict, Tuple, Optional
import time

class EmailAuthChecker:
    def __init__(self, timeout=10):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def check_spf(self, domain: str, ip_address: str = None) -> Dict:
        """
        Check SPF records for a domain
        """
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            spf_record = None
            
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_str = txt_string.decode('utf-8').strip()
                    if txt_str.lower().startswith('v=spf1'):
                        spf_record = txt_str
                        break
            
            if not spf_record:
                return {'exists': False, 'record': None, 'error': 'No SPF record found'}
            
            # Basic SPF validation
            result = {
                'exists': True,
                'record': spf_record,
                'syntax_valid': self.validate_spf_syntax(spf_record),
                'includes_all': 'all' in spf_record.lower()
            }
            
            return result
            
        except dns.resolver.NXDOMAIN:
            return {'exists': False, 'record': None, 'error': 'Domain not found'}
        except dns.resolver.NoAnswer:
            return {'exists': False, 'record': None, 'error': 'No TXT records found'}
        except dns.exception.DNSException as e:
            return {'exists': False, 'record': None, 'error': f'DNS query failed: {str(e)}'}
    
    def check_dkim(self, domain: str, selector: str = 'default') -> Dict:
        """
        Check DKIM records for a domain
        """
        try:
            dkim_query = f'{selector}._domainkey.{domain}'
            answers = self.resolver.resolve(dkim_query, 'TXT')
            
            dkim_record = None
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_str = txt_string.decode('utf-8').strip()
                    if 'v=dkim1' in txt_str.lower():
                        dkim_record = txt_str
                        break
            
            if not dkim_record:
                return {
                    'exists': False, 
                    'record': None, 
                    'error': f'No DKIM record found for selector "{selector}"',
                    'selector_tried': selector
                }
            
            return {
                'exists': True,
                'record': dkim_record,
                'selector': selector,
                'public_key_found': 'p=' in dkim_record.lower()
            }
            
        except dns.resolver.NXDOMAIN:
            return {
                'exists': False, 
                'record': None, 
                'error': f'DKIM selector "{selector}" not found',
                'selector_tried': selector
            }
        except dns.resolver.NoAnswer:
            return {
                'exists': False, 
                'record': None, 
                'error': f'No DKIM records found for selector "{selector}"',
                'selector_tried': selector
            }
        except dns.exception.DNSException as e:
            return {
                'exists': False, 
                'record': None, 
                'error': f'DNS query failed: {str(e)}',
                'selector_tried': selector
            }
    
    def check_dmarc(self, domain: str) -> Dict:
        """
        Check DMARC records for a domain
        """
        try:
            dmarc_query = f'_dmarc.{domain}'
            answers = self.resolver.resolve(dmarc_query, 'TXT')
            
            dmarc_record = None
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_str = txt_string.decode('utf-8').strip()
                    if txt_str.lower().startswith('v=dmarc1'):
                        dmarc_record = txt_str
                        break
            
            if not dmarc_record:
                return {'exists': False, 'record': None, 'error': 'No DMARC record found'}
            
            # Parse DMARC policy
            policy = self.parse_dmarc_policy(dmarc_record)
            
            return {
                'exists': True,
                'record': dmarc_record,
                'policy': policy,
                'pct': self.extract_dmarc_value(dmarc_record, 'pct'),
                'rua': self.extract_dmarc_value(dmarc_record, 'rua'),
                'ruf': self.extract_dmarc_value(dmarc_record, 'ruf')
            }
            
        except dns.resolver.NXDOMAIN:
            return {'exists': False, 'record': None, 'error': 'DMARC record not found'}
        except dns.resolver.NoAnswer:
            return {'exists': False, 'record': None, 'error': 'No DMARC records found'}
        except dns.exception.DNSException as e:
            return {'exists': False, 'record': None, 'error': f'DNS query failed: {str(e)}'}
    
    def check_dkim_with_multiple_selectors(self, domain: str) -> Dict:
        """
        Try multiple common DKIM selectors
        """
        common_selectors = [
            'default', 'google', 'selector1', 'selector2', 
            'k1', 'dkim', 's1', 's2', 'eversrl', 'mail',
            'protonmail', 'zoho', 'sendgrid', 'mandrill'
        ]
        
        all_results = []
        
        for selector in common_selectors:
            result = self.check_dkim(domain, selector)
            all_results.append(result)
            if result['exists']:
                print(f"✅ Found DKIM with selector: {selector}")
                result['all_selectors_tried'] = common_selectors
                return result
        
        # If none found, return comprehensive result
        return {
            'exists': False,
            'record': None,
            'error': f'No DKIM records found after trying {len(common_selectors)} selectors',
            'selectors_tried': common_selectors,
            'all_results': all_results
        }
    
    def validate_spf_syntax(self, spf_record: str) -> bool:
        """Validate basic SPF syntax"""
        try:
            # Basic SPF syntax validation
            if not spf_record.lower().startswith('v=spf1'):
                return False
            
            # Check for common mechanisms
            mechanisms = spf_record.split()[1:]  # Skip 'v=spf1'
            valid_mechanisms = {'a', 'mx', 'ip4', 'ip6', 'include', 'all', 'ptr', 'exists'}
            
            for mech in mechanisms:
                # Handle qualifiers
                if mech.startswith(('+', '-', '~', '?')):
                    mech = mech[1:]
                
                if '=' in mech:
                    key = mech.split('=')[0].lower()
                    if key not in valid_mechanisms:
                        return False
                elif mech.lower() not in valid_mechanisms:
                    return False
            
            return True
        except:
            return False
    
    def parse_dmarc_policy(self, dmarc_record: str) -> str:
        """Extract DMARC policy"""
        policy_match = re.search(r'p=(\w+)', dmarc_record, re.IGNORECASE)
        return policy_match.group(1).lower() if policy_match else 'none'
    
    def extract_dmarc_value(self, dmarc_record: str, key: str) -> str:
        """Extract specific values from DMARC record"""
        match = re.search(f'{key}=([^;]+)', dmarc_record, re.IGNORECASE)
        return match.group(1) if match else None
    
    def comprehensive_check(self, domain: str, from_ip: str = None) -> Dict:
        """
        Perform comprehensive email authentication check
        """
        print(f"🔍 Checking email authentication for: {domain}")
        
        # Perform all checks
        spf_result = self.check_spf(domain, from_ip)
        dkim_result = self.check_dkim_with_multiple_selectors(domain)
        dmarc_result = self.check_dmarc(domain)
        
        results = {
            'domain': domain,
            'timestamp': time.time(),
            'timestamp_human': time.strftime('%Y-%m-%d %H:%M:%S'),
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result
        }
        
        # Calculate security score
        security_score = sum([
            1 if results['spf']['exists'] else 0,
            1 if results['dkim']['exists'] else 0,
            1 if results['dmarc']['exists'] else 0
        ])
        
        # Determine overall status
        if security_score == 3:
            status = 'secure'
            status_description = 'All authentication methods configured'
        elif security_score == 2:
            status = 'moderate'
            status_description = 'Two authentication methods configured'
        elif security_score == 1:
            status = 'weak'
            status_description = 'Only one authentication method configured'
        else:
            status = 'insecure'
            status_description = 'No authentication methods configured'
        
        # Add risk assessment
        risk_level = 'low' if security_score >= 2 else 'medium' if security_score == 1 else 'high'
        
        results['security_score'] = security_score
        results['status'] = status
        results['status_description'] = status_description
        results['risk_level'] = risk_level
        
        return results

    def check_email_auth(self, email_address: str) -> Dict:
        """
        Method for email authentication check
        """
        # Extract domain from email
        if '@' in email_address:
            domain = email_address.split('@')[-1]
        else:
            domain = email_address
            email_address = f"test@{domain}"  # Create a dummy email for display
        
        results = self.comprehensive_check(domain)
        results['checked_email'] = email_address
        results['checked_domain'] = domain
        
        return results

# Standalone function for direct import
def check_email_auth(email_input):
    """
    Standalone function that can handle both email addresses and domains
    """
    checker = EmailAuthChecker()
    
    # If it's a string and contains @, treat as email address
    if isinstance(email_input, str) and '@' in email_input:
        return checker.check_email_auth(email_input)
    
    # If it's bytes, try to extract email from headers
    elif isinstance(email_input, bytes):
        try:
            from email.parser import BytesParser
            from email import policy
            msg = BytesParser(policy=policy.default).parsebytes(email_input)
            from_header = msg.get('From', '')
            # Simple email extraction
            import re
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', from_header)
            if email_match:
                email_addr = email_match.group(0)
                return checker.check_email_auth(email_addr)
            else:
                return {"error": "No email address found in message headers"}
        except Exception as e:
            return {"error": f"Failed to parse email: {str(e)}"}
    
    # Fallback: treat as domain
    else:
        domain = str(email_input)
        return checker.comprehensive_check(domain)

# Test function
def main():
    """
    Test the email authentication checker with common domains
    """
    checker = EmailAuthChecker()
    
    test_domains = [
        'gmail.com',
        'yahoo.com', 
        'microsoft.com',
        'github.com',
        'paypal.com',
        'example.com'  # This one should fail (no records)
    ]
    
    print("🚀 Email Authentication Checker")
    print("=" * 60)
    
    for domain in test_domains:
        print(f"\n📧 Checking: {domain}")
        print("-" * 40)
        
        results = checker.comprehensive_check(domain)
        
        # Display results
        print(f"🛡️  Security Status: {results['status'].upper()} ({results['security_score']}/3)")
        print(f"📊 Risk Level: {results['risk_level'].upper()}")
        
        # SPF
        spf = results['spf']
        print(f"📋 SPF: {'✅' if spf['exists'] else '❌'} {spf.get('record', 'Not found')}")
        if spf.get('error'):
            print(f"   Error: {spf['error']}")
        
        # DKIM
        dkim = results['dkim']
        print(f"🔐 DKIM: {'✅' if dkim['exists'] else '❌'} {dkim.get('record', 'Not found')}")
        if dkim.get('selector'):
            print(f"   Selector: {dkim['selector']}")
        if dkim.get('error'):
            print(f"   Error: {dkim['error']}")
        
        # DMARC
        dmarc = results['dmarc']
        print(f"🛡️  DMARC: {'✅' if dmarc['exists'] else '❌'} {dmarc.get('record', 'Not found')}")
        if dmarc.get('policy'):
            print(f"   Policy: {dmarc['policy']}")
        if dmarc.get('error'):
            print(f"   Error: {dmarc['error']}")
    
    print("\n" + "=" * 60)
    print("✅ Testing completed!")

if __name__ == "__main__":
    main()
