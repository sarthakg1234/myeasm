# @author Sarthak Goyal
# Email : sarthak@startree.ai
# Draft Version 1
import requests
import re
import dns.resolver
import dns.exception
import ssl
import datetime
import pytz
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto

def check_https(url):
    try:
        response = requests.head(url, timeout=5)
        return response.url.startswith('https')
    except requests.ConnectionError:
        return False

def check_hsts(url):
    try:
        response = requests.head(url, timeout=5)
        headers = response.headers
        hsts_header = headers.get('Strict-Transport-Security', '')
        return 'max-age' in hsts_header.lower()
    except requests.ConnectionError:
        return False

def check_csp_headers(url):
    try:
        response = requests.get(url)
        if 'Content-Security-Policy' in response.headers:
            return response.headers['Content-Security-Policy']
        else:
            return None
    except requests.exceptions.RequestException:
        return None

def check_redirect_chain(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        redirect_chain = response.history
        for redirect in redirect_chain:
            if redirect.url.startswith('http://'):
                return True
        if response.url.startswith('http://'):
            return True
        return False
    except requests.ConnectionError:
        return False

def check_csp_for_domain(csp_header, domain):
    domain_regex = re.compile(r'(script-src|default-src|object-src)\s*(?::|[^\'"]*\s*)' + domain)
    if domain_regex.search(csp_header):
        return True
    else:
        return False

def check_http_only_attribute(url):
    try:
        response = requests.get(url, timeout=5)
        cookies = response.cookies
        for cookie in cookies:
            if 'HttpOnly' not in cookie.get_nonstandard_attr('set-cookie', ''):
                return True
        return False
    except requests.ConnectionError:
        return False

def check_content_security_policy(url):
    try:
        response = requests.get(url, timeout=5)
        csp_header = response.headers.get('Content-Security-Policy', '')
        if 'frame-ancestors' not in csp_header.lower():
            return True
        return False
    except requests.ConnectionError:
        return False

def check_x_content_type_options(url):
    try:
        response = requests.head(url, timeout=5)
        x_content_type_options_header = response.headers.get('X-Content-Type-Options', '')
        if 'nosniff' not in x_content_type_options_header.lower():
            return True
        return False
    except requests.ConnectionError:
        return False

def check_spf_softfail_without_dmarc(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10
        spf_response = resolver.resolve(domain, 'TXT')
        for record in spf_response:
            spf_text = record.to_text()
            if 'v=spf1' in spf_text and '~all' in spf_text and not has_dmarc(domain):
                return True
        return False
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return False

def has_dmarc(domain):
    try:
        resolver = dns.resolver.Resolver()
        dmarc_response = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        return any('v=dmarc' in record.to_text() for record in dmarc_response)
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return False

def check_tls_version(url):
    try:
        response = requests.get(url, stream=True)
        ssl_context = response.raw._connection.sock._sslobj.context
        tls_version = ssl_context.protocol
        if tls_version in ['TLSv1', 'TLSv1.1']:
            print(f"Weak TLS version ({tls_version}) is used.")
        else:
            print(f"Secure TLS version ({tls_version}) is used.")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def check_certificate_expiry(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        if cert:
            cert_dict = ssl._ssl._test_decode_cert(cert)
            expire_date = datetime.datetime.utcfromtimestamp(cert_dict['notAfter'])
            return expire_date
        else:
            print(f"No certificate found for {domain}.")
            return None
    except Exception as e:
        print(f"Error retrieving certificate for {domain}: {e}")
        return None

def check_certificate_validity(ip_address):
    try:
        cert = ssl.get_server_certificate((ip_address, 443))
        x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        not_valid_before = x509_cert.not_valid_before_utc
        not_valid_after = x509_cert.not_valid_after_utc

        issue_date_threshold = datetime.datetime(2020, 9, 1, tzinfo=pytz.utc)

        if not_valid_before > issue_date_threshold:
            validity_period = not_valid_after - not_valid_before
            if validity_period.days > 398:
                print(f"The certificate for {ip_address} issued after September 1, 2020 is valid for more than 398 days.")
                print("Consider replacing the certificate.")
            else:
                print(f"The certificate for {ip_address} issued after September 1, 2020 is valid for {validity_period.days} days.")
        else:
            print(f"The certificate for {ip_address} was issued before September 1, 2020. No validity check performed.")

    except Exception as e:
        print(f"Error checking certificate validity for {ip_address}: {e}")

def supports_weak_cipher_suite(ip_address):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip_address, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=ip_address) as ssock:
                cipher = ssock.cipher()
                return cipher[0] in ('AES', 'DES', '3DES', 'RC4')
    except Exception as e:
        print(f"Error checking cipher suite for {ip_address}: {e}")
        return False

def has_revocation_controls(ip_address):
    try:
        cert = ssl.get_server_certificate((ip_address, 443))
        x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        crldp = x509_cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
        ocsp = x509_cert.extensions.get_extension_for_oid(x509.ExtensionOID.OCSP_NO_CHECK)

        return crldp is not None or ocsp is not None
    except x509.ExtensionNotFound as e:
        print(f"Certificate for {ip_address} does not include revocation controls.")
        return False
    except Exception as e:
        print(f"Error checking revocation controls: {e}")
        return False

def is_self_signed(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        subject = x509.get_subject().get_components()
        issuer = x509.get_issuer().get_components()
        return subject == issuer
    except Exception as e:
        print(f"Error checking if certificate is self-signed: {e}")
        return False

def check_domain_security(domain):
    print(f"Checking security aspects for domain: {domain}")
    url = f"https://{domain}"
    
    # Check HTTPS
    if check_https(url):
        print("Domain uses HTTPS")
    else:
        print("Domain does not use HTTPS")

    # Check HSTS
    if check_hsts(url):
        print("Domain has HSTS implemented")
    else:
        print("Domain does not have HSTS implemented")

    # Check CSP headers
    csp_header = check_csp_headers(url)
    if csp_header:
        print("CSP Headers are present:")
        print(csp_header)
    else:
        print("CSP Headers are not present.")

    # Check Redirect Chain
    if check_redirect_chain(url):
        print("Domain has HTTP in the redirect chain")
    else:
        print("Domain does not have HTTP in the redirect chain")

    # Add more security checks as needed...

if __name__ == "__main__":
    domain_to_check = "yourdomain.com"
    check_domain_security(domain_to_check)
