import requests

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

def main():
    website_url = "https://thirdeye.demo.teprod.startree.cloud/home"
    
    if check_https(website_url):
        print(f"{website_url} uses HTTPS")
    else:
        print(f"{website_url} does not use HTTPS")

    if check_hsts(website_url):
        print(f"{website_url} has HSTS implemented")
    else:
        print(f"{website_url} does not have HSTS implemented")

    csp_headers = check_csp_headers(website_url)
    if csp_headers:
        print("CSP Headers are present:")
        print(csp_headers)
    else:
        print("CSP Headers are not present.")

    if check_redirect_chain(website_url):
        print(f"{website_url} has HTTP in the redirect chain")
    else:
        print(f"{website_url} does not have HTTP in the redirect chain")

if __name__ == "__main__":
    main()
