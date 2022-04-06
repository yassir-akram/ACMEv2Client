import os
import pathlib
import functools
from time import sleep
import requests
import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

from dnslib import DNSLabel, QTYPE, RD, RR
from dnslib import A, AAAA, CNAME, MX, NS, SOA, TXT


class Acmev2Client(object):
  def __init__(s, 
               acme_server_dir_url, 
               server_root_dir,
               account_key_path=None, 
               check=True, 
               dns_resolver=None):
    s.acme_server_dir_url = acme_server_dir_url
    s.__get_directory()
    
    s.server_root_dir = server_root_dir

    s.key = s.__generate_key() if account_key_path is None\
            else s.__load_pem_key(account_key_path)
    
    def bin_sign(data):
      signature = s.key.sign(data, 
                             signature_algorithm=ec.ECDSA(hashes.SHA256()))
      vr, vs = utils.decode_dss_signature(signature)
      return vr.to_bytes(length=32, byteorder="big") + vs.to_bytes(length=32, byteorder="big")
    
    s.sign = bin_sign

    alg = "ES256"
    jwk = {"kty": "EC",
           "crv": "P-256",
           "x": s.b64enc(int.to_bytes(s.key.public_key().public_numbers().x,
                                      length=32,
                                      byteorder="big")),
           "y": s.b64enc(int.to_bytes(s.key.public_key().public_numbers().y,
                                      length=32,
                                      byteorder="big"))}
    jwk_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(jwk_json.encode('utf-8'))
    s.jwk_thumberprint = s.b64enc(digest.finalize())

    s.__body = {}
    s.__body["payload"] = ""
    s.__body["protected"] = ""
    s.__body["signature"] = ""
    s.__protected = {"url": "",
                     "alg": alg,
                     "nonce": s.get_nonce(),
                     "jwk": jwk}

    s.__create_account()
    s.dns_resolver = dns_resolver
  
  @staticmethod
  def b64enc(b):
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip("=")

  def __get_directory(s):
    resp = requests.get(s.acme_server_dir_url)#, verify="pebble.minica.pem")
    assert(resp.status_code == 200)
    s.directory = resp.json()

  def get_nonce(s):
    resp = requests.head(s.directory["newNonce"])#, verify="pebble.minica.pem")
    assert(resp.status_code == 200)
    return resp.headers["Replay-Nonce"]

  def __post(s, url, payload=None):
    s.__body["payload"] = s.b64enc(json.dumps(payload).encode("utf-8")) if payload is not None else ""
    s.__protected["url"] = url
    s.__body["protected"] = s.b64enc(json.dumps(s.__protected).encode("utf-8"))
    message_to_sign = f"{s.__body['protected']}.{s.__body['payload']}".encode("utf-8")
    s.__body["signature"] = s.b64enc(s.sign(message_to_sign))

    req = requests.Request(method="POST",
                           url=url,
                           headers={"Content-Type": "application/jose+json"},
                           json=s.__body)
    
    sess = requests.Session()
    #sess.verify = "pebble.minica.pem"
    resp = sess.send(req.prepare())
    
    s.__protected["nonce"] = resp.headers["Replay-Nonce"]
    return resp
  
  def __poll(s, obj, obj_url, waiting_states):
    while obj["status"] in waiting_states:
      sleep(1)
      resp = s.__post(url=obj_url)
      assert(resp.status_code == 200)
      obj = resp.json()
    return obj
    
  def __create_account(s):
    resp = s.__post(url=s.directory["newAccount"],
                    payload={"termsOfServiceAgreed": True})
    assert(resp.status_code in {200, 201})
    assert(resp.json()["status"] == "valid")
    s.account_url = resp.headers["Location"]
    del s.__protected["jwk"]
    s.__protected["kid"] = s.account_url
    
  def __submit_order(s, domains):
    resp = s.__post(url=s.directory["newOrder"],
                    payload={"identifiers": [{"type": "dns",
                                              "value": domain} for domain in domains]})
    assert(resp.status_code == 201)
    order_url = resp.headers["Location"]
    order = resp.json()
    assert(order["status"] in {"pending", "ready", "processing",
                               "valid", "invalid"})
    if order["status"] == "invalid":
      raise Exception("Order rejected!")
    return order, order_url
  
  def __fetch_authorization(s, auth_url):
    resp = s.__post(url=auth_url)
    assert(resp.status_code == 200)
    auth = resp.json()
    assert(auth["status"] in {"pending", "valid", "invalid"})
    if auth["status"] == "invalid":
      raise Exception("Authorization rejected!")
    return auth, auth_url
  
  def __select_challenge(s, auth, challenge_type):
    challenges = {challenge["type"]: challenge
                  for challenge in auth["challenges"]}
    challenge =  challenges[challenge_type]
    assert(challenge["status"] in {"pending", "processing", "valid", "invalid"})
    if challenge["status"] == "invalid":
      raise Exception("Challenge rejected!")
    return challenge, challenge["url"]
  
  def __do_http01_challenge(s, token):
    filepath = os.path.join(s.server_root_dir,
                            f".well-known/acme-challenge/{token}")
    content = f"{token}.{s.jwk_thumberprint}"
    dir_path = os.path.join(s.server_root_dir, ".well-known/acme-challenge")
    pathlib.Path(dir_path).mkdir(parents=True, exist_ok=True)
    with open(filepath, "wt") as f:
      f.write(content)

  def __do_dns01_challenge(s, domain, token):
    content = f"{token}.{s.jwk_thumberprint}"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(content.encode('utf-8'))
    chl_domain = f"_acme-challenge.{domain}"
    s.dns_resolver.zones[DNSLabel(chl_domain)] = [RR(chl_domain, QTYPE.TXT, rdata=TXT(s.b64enc(digest.finalize())), ttl=60)]
    
  def __validate_challenge(s, challenge):
    challenge_url = challenge["url"]
    resp = s.__post(url=challenge_url,
                    payload={})
    assert(resp.status_code == 200)
    challenge = resp.json()
    return challenge

  @staticmethod
  def __generate_key():
    return ec.generate_private_key(ec.SECP256R1())
  
  @staticmethod
  def __load_pem_key(key_path):
    with open(key_path, "rt") as f:
      key = serialization.load_pem_private_key(f.read().encode("utf-8"), password=None)
    return key

  def __save_private_key_pem(private_key, key_path):
    serialized_private = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption())
      #encryption_algorithm=serialization.BestAvailableEncryption(b'testpassword'))
    with open(key_path, "wt") as f:
      f.write(serialized_private.decode("utf-8"))
    

  @staticmethod
  def __generate_key_csr(domains, output_path):
    key = Acmev2Client.__generate_key()
    key_path = os.path.join(output_path, "server_privatekey.pem")
    Acmev2Client.__save_private_key_pem(key, key_path)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
      #x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
      #x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
      #x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
      #x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
      x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ])).add_extension(
      x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
      critical=False,
    ).sign(key, hashes.SHA256())
    return csr
  
  @staticmethod
  def __load_pem_csr(csr_path):
    with open(csr_path, "rt") as f:
      return x509.load_pem_x509_certificate(f.read())
  
  def __finilize_order(s, order, csr):
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    resp = s.__post(url=order["finalize"],
                    payload={"csr": s.b64enc(csr_der)})
    assert(resp.status_code == 200)
    order = resp.json()
    return order
  
  def __download_certificate(s, order):
    certificate_url = order["certificate"]
    resp = s.__post(url=certificate_url)
    assert(resp.status_code == 200)
    s.certificate_pem = resp.text
    cert_path = os.path.join(output_path, "server_certificate.pem")
    with open(cert_path, "wt") as f:
      f.write(s.certificate_pem)

  def revoke_certificate(s, crt):
    crt_der = crt.public_bytes(serialization.Encoding.DER)
    resp = s.__post(url=s.directory['revokeCert'], 
                    payload={'certificate':  s.b64enc(crt_der)})
    assert(resp.status_code == 200)
 
  def register_domain(s, domain, csr_path=None, 
                      challenge_pref=["http-01", "dns-01"], 
                      output_path="."):
    return s.register_domains([domain], csr_path, 
                              challenge_pref=challenge_pref, 
                              output_path=output_path)
  
  def register_domains(s, domains, csr_path=None, 
                       challenge_pref=["http-01", "dns-01"], 
                       output_path="."):
    order, order_url = s.__submit_order(domains)
    if order["status"] == "pending":
      for auth_url in order["authorizations"]:
        auth, auth_url = s.__fetch_authorization(auth_url)
        if auth["status"] == "pending":
          domain = auth["identifier"]["value"]
          for challenge_type in challenge_pref:
            try:
              challenge, challenge_url = s.__select_challenge(auth, challenge_type)
            except:
              continue
            if challenge["status"] == "pending":
              if challenge_type == "http-01":
                s.__do_http01_challenge(challenge["token"])
              if challenge_type == "dns-01":
                s.__do_dns01_challenge(domain, challenge["token"])
              challenge = s.__validate_challenge(challenge)
              challenge = s.__poll(challenge, challenge_url, {"pending", "processing"})
              if challenge["status"] == "invalid": raise Exception("Challenge rejected!")
            break
          else: raise Exception("No challenge found!")
          auth = s.__poll(auth, auth_url, {"pending"})
          if auth["status"] == "invalid": raise Exception("Authorization rejected!")
      order = s.__poll(order, order_url, {"pending"})
      if order["status"] == "invalid": raise Exception("Order rejected!")
    assert(order["status"] in {"ready", "processing", "valid"})
    if order["status"] == "ready":
      csr = s.__load_pem_csr(csr_path) if csr_path else s.__generate_key_csr(domains, output_path)
      order = s.__finilize_order(order, csr)
      order = s.__poll(order, order_url, {"ready", "processing"})
      if order["status"] == "invalid": raise Exception("Order rejected!")
    assert(order["status"] == "valid")
    s.__download_certificate(order)

