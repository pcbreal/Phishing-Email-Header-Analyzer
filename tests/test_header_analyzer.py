from email import policy
from email.parser import BytesParser
from src.header_analyzer import extract_auth_results, extract_received_chain

def parse(text: str):
    return BytesParser(policy=policy.default).parsebytes(text.encode())

def test_auth_parsing():
    msg = parse("""Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass
From: a@b.com
""")
    auth = extract_auth_results(msg)
    assert auth["spf"] == "pass"
    assert auth["dkim"] == "pass"
    assert auth["dmarc"] == "pass"

def test_received_chain():
    msg = parse("""Received: from a (1.2.3.4)
Received: from b (5.6.7.8)
From: a@b.com
""")
    chain = extract_received_chain(msg)
    assert len(chain) == 2
