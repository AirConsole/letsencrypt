#!/usr/bin/env python
#
# Copyright 2016 N-Dream AG Inc.
# Based on https://github.com/diafygi/acme-tiny
import os

"""
INSTALLATION:

Add the following to your app.yaml:

handlers:
- url: /\.well\-known\/acme\-challenge\/.*
  script: letsencrypt.app

To get a new appengine https certificate for your domain go to:
www.yourdomain.com/.well-known/acme-challenge/
"""

if 'SERVER_SOFTWARE' in os.environ:
  import webapp2
  from google.appengine.api import users
  from google.appengine.api import memcache
  import random
  import hashlib
  import logging

  class AcmeChallengeCreatorHandler(webapp2.RequestHandler):
    def get(self):
      if self.request.get("script"):
        self.response.content_type = 'text/plain'
        source = __file__
        if source.endswith(".pyc"):
          source = source[:-1]
        self.response.out.write(open(source).read())
        return
      user = users.get_current_user()
      if user and users.is_current_user_admin():
        secret = memcache.get("letsencrypt.py_secret")
        if not secret:
          secret = ''.join(random.SystemRandom().choice(
              "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                           for _ in xrange(64))
          memcache.set("letsencrypt.py_secret", secret)
        domain = self.request.host
        if domain.endswith(".appspot.com"):
          self.response.out.write("You need to run this script on your domain, not appspot.com.")
          return
        if os.environ.get('SERVER_SOFTWARE','').startswith('Development'):
          self.response.out.write("This script can only be run in production.")
          return
        self.response.out.write("""
  Run the following command in a shell (curl and openssl required):
  <pre style='background-color: #eee; padding: 10px'>curl -s http://%s/.well-known/acme-challenge/?script=1 | python - --domain %s --secret %s</pre>
  You can also run this command in the <a href='https://cloud.google.com/shell/docs/quickstart'>Google Cloud Shell</a>
  """ % (domain, domain, secret))
      else:
        self.redirect(users.create_login_url("/.well-known/acme-challenge/"))

    def post(self):
      key = self.request.get("key")
      value = self.request.get("value")
      signature = self.request.get("signature")
      secret = memcache.get("letsencrypt.py_secret")
      if key and value and hashlib.sha512(key + value + secret).hexdigest() == signature:
        logging.info("Setting challenge for " + key + " to " + value)
        memcache.set("letsencrypt.py_challenge_" + key, value)
      else:
        self.error(403)


  class AcmeChallengeHandler(webapp2.RequestHandler):
    def get(self):
      key = self.request.path.split("/")[-1]
      value = memcache.get("letsencrypt.py_challenge_" + key)
      if value:
        self.response.content_type = 'text/plain'
        self.response.out.write(value)
      else:
        self.error(404)




  app = webapp2.WSGIApplication([
    ('/\.well\-known\/acme\-challenge\/', AcmeChallengeCreatorHandler),
    ('/\.well\-known\/acme\-challenge\/.+', AcmeChallengeHandler),
  ], debug=True)

else:
  import argparse, subprocess, json, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
  from urllib2 import urlopen, Request
  import urllib
  import hashlib

  #DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
  DEFAULT_CA = "https://acme-v01.api.letsencrypt.org"
  INTERMEDIATE_CERT = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem"

  LOGGER = logging.getLogger(__name__)
  LOGGER.addHandler(logging.StreamHandler())
  LOGGER.setLevel(logging.INFO)

  def get_crt(domain, secret, log=LOGGER, CA=DEFAULT_CA):
    try:
      ts = str(time.time())
      account_key = "account.key" + ts
      domain_key = "domain.key" + ts
      csr = "domain.csr" + ts
      def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

      log.info("Generate account key...")
      proc = subprocess.Popen(["openssl", "genrsa", "2048", "-noout", "-text"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      account_key_contents, err = proc.communicate()
      if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
      with open(account_key, "w") as account_key_file:
        account_key_file.write(account_key_contents)

      log.info("Generate domain key...")
      proc = subprocess.Popen(["openssl", "genrsa", "2048", "-noout", "-text"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      domain_key_contents, err = proc.communicate()
      if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
      with open(domain_key, "w") as domain_key_file:
        domain_key_file.write(domain_key_contents)

      log.info("Generate csr...")
      proc = subprocess.Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key, "-subj", "/CN=" + domain],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      csr_contents, err = proc.communicate()
      if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
      with open(csr, "w") as csr_file:
        csr_file.write(csr_contents)

      # parse account key to get public key
      log.info("Parsing account key...")
      proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      out, err = proc.communicate()
      if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
      pub_hex, pub_exp = re.search(
          r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
          out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
      pub_exp = "{0:x}".format(int(pub_exp))
      pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
      header = {
        "alg": "RS256",
        "jwk": {
          "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
          "kty": "RSA",
          "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
      }
      accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
      thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

      # helper function make signed requests
      def _send_signed_request(url, payload):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", account_key],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode('utf8'))
        if proc.returncode != 0:
          raise IOError("OpenSSL Error: {0}".format(err))
        data = json.dumps({
          "header": header, "protected": protected64,
          "payload": payload64, "signature": _b64(out),
        })
        try:
          resp = urlopen(url, data.encode('utf8'))
          return resp.getcode(), resp.read()
        except IOError as e:
          return getattr(e, "code", None), getattr(e, "read", e.__str__)()

      # find domains
      log.info("Parsing CSR...")
      proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      out, err = proc.communicate()
      if proc.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(csr, err))
      domains = set([])
      common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out.decode('utf8'))
      if common_name is not None:
        domains.add(common_name.group(1))
      subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
      if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
          if san.startswith("DNS:"):
            domains.add(san[4:])

      # get the certificate domains and expiration
      log.info("Registering account...")
      code, result = _send_signed_request(CA + "/acme/new-reg", {
        "resource": "new-reg",
        "agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf",
      })
      if code == 201:
        log.info("Registered!")
      elif code == 409:
        log.info("Already registered!")
      else:
        raise ValueError("Error registering: {0} {1}".format(code, result))

      # verify each domain
      for domain in domains:
        log.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result = _send_signed_request(CA + "/acme/new-authz", {
          "resource": "new-authz",
          "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
          raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

        # make the challenge file
        challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)

        log.info("Setting challenge {0}...".format(domain))
        url = "http://" + domain + "/.well-known/acme-challenge/"
        data = urllib.urlencode({
          "key": token,
          "value": keyauthorization,
          "signature": hashlib.sha512(token + keyauthorization + secret).hexdigest()
        })
        try:
          req = Request(url, data)
          response = urlopen(req)
          if response.getcode() != 200:
            raise IOError()
        except IOError as e:
          raise ValueError("Error setting challenge on " + url)

        # check that the file is in place
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
        try:
          resp = urlopen(wellknown_url)
          resp_data = resp.read().decode('utf8').strip()
          assert resp_data == keyauthorization
        except (IOError, AssertionError):
          os.remove(wellknown_path)
          raise ValueError("Couldn't download {0}".format(
              wellknown_url))

        # notify challenge are met
        code, result = _send_signed_request(challenge['uri'], {
          "resource": "challenge",
          "keyAuthorization": keyauthorization,
        })
        if code != 202:
          raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

        # wait for challenge to be verified
        while True:
          try:
            resp = urlopen(challenge['uri'])
            challenge_status = json.loads(resp.read().decode('utf8'))
          except IOError as e:
            raise ValueError("Error checking challenge: {0} {1}".format(
                e.code, json.loads(e.read().decode('utf8'))))
          if challenge_status['status'] == "pending":
            time.sleep(2)
          elif challenge_status['status'] == "valid":
            log.info("{0} verified!".format(domain))
            break
          else:
            raise ValueError("{0} challenge did not pass: {1}".format(
                domain, challenge_status))

      # get the new certificate
      log.info("Signing certificate...")
      proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      csr_der, err = proc.communicate()
      code, result = _send_signed_request(CA + "/acme/new-cert", {
        "resource": "new-cert",
        "csr": _b64(csr_der),
      })
      if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))

      # return signed certificate!
      log.info("Certificate signed!")
      log.info("Fetching intermediate certificate")
      try:
        intermediate = urlopen(INTERMEDIATE_CERT).read()
      except (IOError, AssertionError):
        raise ValueError("Couldn't download intermediate certificate")

      sys.stdout.write("\n\nPEM encoded X.509 public key certificate:\n\n")
      sys.stdout.write("-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n".format(
          "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64))))
      sys.stdout.write(intermediate)
      sys.stdout.write("\n\nUnencrypted PEM encoded RSA private key:\n\n")
      sys.stdout.write(domain_key_contents)
      sys.stdout.write("\n\nEnter the values above in https://console.cloud.google.com/appengine/settings/certificates\n")

    finally:
      for file in [account_key, domain_key, csr]:
        try:
          os.remove(file)
        except:
          pass

  def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("Semi-Automates 'Let's Encrypt' for Google AppEngine\n"+
                                    "This script is based on https://github.com/diafygi/acme-tiny.")
    )
    parser.add_argument("--domain", required=True, help="the domain which you would like to get the certicate for")
    parser.add_argument("--secret", required=True, help="The secret you got from the /.well-known/acme-challenge/ page on your domain")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--ca", default=DEFAULT_CA, help="certificate authority, default is Let's Encrypt")
    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)
    get_crt(args.domain, args.secret, log=LOGGER, CA=args.ca)

  if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])

