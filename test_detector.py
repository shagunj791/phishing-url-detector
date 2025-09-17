from detector import is_phishy

def test_safe_url():
    assert is_phishy("https://www.google.com") == "Safe "

def test_suspicious_url():
    assert is_phishy("http://login-secure-update.google.com") == "Suspicious "

def test_dangerous_url():
    assert is_phishy("http://192.168.1.1/login") == "Dangerous "
