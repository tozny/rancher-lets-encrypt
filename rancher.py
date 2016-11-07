#! /usr/bin/env python2.7

# This python service is responsible for managing lets encrypt certificates.

import time
import socket
from datetime import datetime
import os
import subprocess
import json
import requests
import uuid
import errno
from OpenSSL import crypto
from requests.auth import HTTPBasicAuth
from sets import Set
from random import shuffle

try:
    RANCHER_URL = os.environ['CATTLE_URL']
    RANCHER_ACCESS_KEY = os.environ['CATTLE_ACCESS_KEY']
    RANCHER_SECRET_KEY = os.environ['CATTLE_SECRET_KEY']
    DOMAINS = os.environ['DOMAINS']
    # convert renew days -> seconds
    RENEW_THRESHOLD = int(os.environ['RENEW_BEFORE_DAYS']) * (24 * 60 * 60)
    LOOP_TIME = int(os.environ['LOOP_TIME'])
    CERTBOT_WEBROOT = os.environ['CERTBOT_WEBROOT']
    CERTBOT_EMAIL = os.environ['CERTBOT_EMAIL']
    STAGING = os.environ['STAGING'] == "True"
    DYNAMIC_CONFIG = os.environ['DYNAMIC_CONFIG'] == "True"

except KeyError as e:
    print "Could not find an Environment variable set."
    print e


class RancherService:

    def __init__(self):
        user_agent = "rancher-lets-encrypt/0.1"

        self.headers_want_json = {
            'User-Agent': user_agent,
            'Accept': 'application/json'
        }
        self.headers_sending_json = {
            'User-Agent': user_agent,
            'Content-Type': 'application/json'
        }
        self.headers = {
            'User-Agent': user_agent
        }
        self.static_domains = Set()
        self.internal_challenge_value = str(uuid.uuid4())

    def initialize(self):
        if DOMAINS != '':
            for domain in DOMAINS.split(','):
                self.static_domains.add(domain)
        self.acme_challenge_write()

    def acme_challenge_write(self):
        acme_directory = CERTBOT_WEBROOT + "/.well-known/acme-challenge"
        try:
            os.makedirs(acme_directory)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise exc
        with open(acme_directory + '/index.html', 'w') as acme_index_file:
            print >>acme_index_file, self.internal_challenge_value

    def auth(self):
        '''
        return a http auth object
        '''
        return HTTPBasicAuth(RANCHER_ACCESS_KEY, RANCHER_SECRET_KEY)

    def get_certificate(self):
        '''
        return json(python dict) of of certificate listing api endpoint
        '''
        url = "{0}/certificate".format(RANCHER_URL)
        r = requests.get(url=url, auth=self.auth(), headers=self.headers, timeout=60)
        return r.json()['data']

    def get_issuer_for_certificates(self):
        '''
        get the "issuer": "CN=Fake LE Intermediate X1",
        field name for a given server hostname

        returns: dict where key is server hostname and value is issuer
        Will always return one issuer per hostname in Rancher API.
        '''
        issuers = {}
        certificates = self.get_certificate()
        for cert in certificates:
            server = cert['CN']
            if server in issuers:
                # we have duplicate certs, so we need to decide which cert is the latest one.
                prev_cert_created = int(issuers[server]['created'])
                next_cert_created = int(cert['createdTS'])
                if next_cert_created - prev_cert_created < 0:
                    # previous cert is newer, so keep that one
                    # nothing changes
                    continue
                else:
                    # next cert is newer, so add that one
                    issuers[server]['issuer'] = cert['issuer']
                    issuers[server]['created'] = cert['createdTS']
            else:
                # not a duplicate server cert name
                issuers[server] = {}
                issuers[server]['issuer'] = cert['issuer']
                issuers[server]['created'] = cert['createdTS']
        return issuers

    def rancher_certificate_expired(self, server):
        returned_json = self.get_certificate()
        for certificate in returned_json:
            cn = certificate['CN']
            if server == cn:
                # found the cert we want to verify
                expires_at = certificate['expiresAt']
                timestamp = datetime.strptime(expires_at, '%a %b %d %H:%M:%S %Z %Y')
                expiry = int(timestamp.strftime("%s"))
                print "Found cert: {0}, Expiry: {1}".format(cn, expiry)
                now = int(time.time())
                if self.expiring(expiry):
                    return True
                else:
                    return False
            else:
                # a cert we dont care about since it doesnt match server cn
                continue

    def delete_cert(self, server):
        '''
        Delete existing cert from the server.
        '''
        print "Deleting {0} cert from Rancher API".format(server)
        url = "{0}/projects/{1]/certificates/{2}".format(RANCHER_URL, self.get_project_id(), self.get_certificate_id(server))
        r = requests.delete(url=url, auth=self.auth(), headers=self.headers, timeout=60)
        print "Delete cert status code: {0}".format(r.status_code)
        print "Sleeping for two minutes because rancher sucks and takes FOREVER to purge a deleted certificate"
        time.sleep(120)

    def get_certificate_id(self, server):
        '''
        Get Rancher assigned certificate id for a given certificate.
        '''
        certs = self.get_certificate()
        for cert in certs:
            if cert['CN'] == server:
                return cert['id']
        return None

    def expiring(self, cert_time):
        '''
        returns True if the cert is expired and False if the cert is not
        This also tests to see if the cert is *going* to expire, and returns the same Boolean.
        '''
        now = int(time.time())
        if(cert_time - now <= RENEW_THRESHOLD):
            return True
        elif(cert_time - now < 0):
            return True
        else:
            return False

    def renew_certificate(self, server):
        print "Renewing certificate for {0}".format(server)
        self.create_cert(server)

    def check_cert_files_exist(self, server):
        '''
        check if certs files already exist on disk. If they are on disk and not in rancher, publish them in rancher.
        '''
        cert_dir = '/etc/letsencrypt/live/{0}/'.format(server)
        cert = '{0}/cert.pem'.format(cert_dir)
        privkey = '{0}/privkey.pem'.format(cert_dir)
        fullchain = '{0}/fullchain.pem'.format(cert_dir)
        return (os.path.isdir(cert_dir) and os.path.isfile(cert) and os.path.isfile(privkey) and os.path.isfile(fullchain))

    def cert_manager_loop(self):
        while True:
            self.cert_manager()
            print "Sleeping: {0} seconds...".format(LOOP_TIME)
            time.sleep(LOOP_TIME)

    def domains_to_manage(self):
        domains = list(self.static_domains.union(self.get_dynamic_domains()))
        # Randomize the order in which we handle domains, that way if some domains cause problems
        # other domains may still get a chance to run before a domain which causes problems
        shuffle(domains)
        return domains

    def cert_manager(self):
        '''
        Check that the server in DOMAINS have certificates in Rancher UI.
        If they do not have a cert, it is a new server, and we need to create a cert.
        If the cert already exists, we should check that it is not going to expire.

        This is where almost all of the logic of the service is for cert issuance, renewal,
        and rancher cert management.
        '''
        servers = self.domains_to_manage()
        rancher_cert_servers = self.get_rancher_certificate_servers()
        issuers = self.get_issuer_for_certificates()
        for server in servers:
            if self.check_cert_files_exist(server):
                # local copy of cert
                if server not in rancher_cert_servers:
                    # cert not in rancher
                    cert = self.read_cert(server)
                    if self.local_cert_expired(cert):
                        # local copy (expired cert)
                        self.create_cert(server)
                        self.post_cert(server)
                    else:
                        # local copy (not expired cert)
                        self.post_cert(server)
                else:
                    # cert in rancher
                    server_cert_issuer = issuers[server]['issuer']
                    if "Fake" in server_cert_issuer and not STAGING:
                        # upgarde staging cert to production
                        print "Upgrading staging cert to production for {0}".format(server)
                        self.create_cert(server)
                        self.post_cert(server)

                    elif("Let's Encrypt Authority X3" not in server_cert_issuer and
                         "Let's Encrypt Authority X4" not in server_cert_issuer and
                         not STAGING):
                        # we have a self-signed certificate we should replace with a prod certificate.
                        # this should only happen once on initial rancher install.
                        print "Replacing self-signed certificate: {0}, {1} with production LE cert".format(server, server_cert_issuer)
                        self.create_cert(server)
                        self.post_cert(server)

                    elif self.rancher_certificate_expired(server):
                        # rancher cert expired
                        cert = self.read_cert(server)
                        if self.local_cert_expired(cert):
                            # local cert expired
                            self.create_cert(server)
                            self.post_cert(server)
                        else:
                            # local cert not expired
                            self.post_cert(server)
            else:
                # no local copy of cert
                self.create_cert(server)
                self.post_cert(server)

    def create_cert(self, server):
        print "need to create cert for {0}".format(server)
        if self.acme_challenge_failed(server):
            return

        # TODO this is incredibly hacky. Certbot is python code so there should be a way to do this without shelling
        # out to the cli certbot tool. (certbot docs suck btw)
        # https://www.metachris.com/2015/12/comparison-of-10-acme-lets-encrypt-clients/#client-simp_le maybe?
        if(STAGING):
            proc = subprocess.Popen(["certbot", "certonly", "--webroot", "-w", CERTBOT_WEBROOT, "--text", "-d", server,
                                     "-m", CERTBOT_EMAIL, "--agree-tos", "--renew-by-default", "--staging"],
                                    stdout=subprocess.PIPE)
        else:
            # production
            proc = subprocess.Popen(["certbot", "certonly", "--webroot", "-w", CERTBOT_WEBROOT, "--text", "-d", server,
                                     "-m", CERTBOT_EMAIL, "--agree-tos", "--renew-by-default"], stdout=subprocess.PIPE)
        # wait for the process to return
        com = proc.communicate()[0]
        # read cert in from file
        if proc.returncode == 0:
            # made cert hopefully *crosses fingers*
            print "certbot seems to have run with exit code 0"
        else:
            print "an error occured during cert creation."
        # print stdout from subprocess
        print com

    def local_cert_expired(self, cert_string):
        '''
        if there is a certificate in /etc/letsencrypt, we should check that it is itself valid and not about to expire.
        '''
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_string)
        timestamp = datetime.strptime(cert.get_notAfter(), "%Y%m%d%H%M%SZ")
        expiry = int(timestamp.strftime("%s"))
        if(self.expiring(expiry)):
            return True
        else:
            return False

    def post_cert(self, server):
        '''
        POST a certificate to the Rancher API.
        '''
        if not self.check_cert_files_exist(server):
            print "Could not find cert files for " + server + " inside post_cert method!"
            return
        if self.local_cert_expired(self.read_cert(server)):
            print "Wanted to push a certificate for " + server + " to rancher, but it was already expired :("

        # check if the cert exists in Rancher.
        cert_id = self.get_certificate_id(server)
        if(cert_id is not None):
            # the cert exists in rancher, do PUT to update it
            url = "{0}/projects/{1}/certificates/{2}".format(RANCHER_URL, self.get_project_id(), cert_id)
            request_type = requests.put
        else:
            # create the cert for the first time, do POST
            url = "{0}/projects/{1}/certificate".format(RANCHER_URL, self.get_project_id())
            request_type = requests.post

        json_structure = {}
        json_structure['certChain'] = self.read_fullchain(server)
        json_structure['cert'] = self.read_cert(server)
        json_structure['key'] = self.read_privkey(server)
        json_structure['type'] = 'certificate'
        json_structure['name'] = server
        json_structure['created'] = None
        json_structure['description'] = None
        json_structure['kind'] = None
        json_structure['removed'] = None
        json_structure['uuid'] = None

        r = request_type(url=url, data=json.dumps(json_structure), headers=self.headers_sending_json, auth=self.auth(),
                         timeout=60)
        print "HTTP status code: {0}".format(r.status_code)

    def get_project_id(self):
        '''
        get /projects/<id>/certificate
        --> /projects/1a5/certificate
        '''
        url = "{0}/projects".format(RANCHER_URL)
        r = requests.get(url=url, auth=self.auth(), headers=self.headers, timeout=60)
        j = r.json()
        return j['data'][0]['id']

    def read_cert(self, server):
        '''
        Read cert.pem file from letsencrypt directory
        and return the contents as a string
        '''
        cert_file = "/etc/letsencrypt/live/{0}/{1}".format(server, "cert.pem")
        if(os.path.isfile(cert_file)):
            # read files and post the correct info to populate rancher
            with open(cert_file, 'r') as openfile:
                cert = openfile.read().rstrip('\n')
            return cert
        else:
            print "Could not find file: {0}".format(cert_file)
            return None

    def read_privkey(self, server):
        '''
        Read privkey.pem file from letsencrypt directory
        and return the contents as a string
        '''
        privkey_file = "/etc/letsencrypt/live/{0}/{1}".format(server, "privkey.pem")
        if(os.path.isfile(privkey_file)):
            # read files and post the correct info to populate rancher
            with open(privkey_file, 'r') as openfile:
                privkey = openfile.read().rstrip('\n')
            return privkey
        else:
            print "Could not find file: {0}".format(privkey_file)
            return None

    def read_fullchain(self, server):
        '''
        Read fullchain.pem file from letsencrypt directory.
        and return the contents as a string
        '''
        fullchain_file = "/etc/letsencrypt/live/{0}/{1}".format(server, "fullchain.pem")
        if(os.path.isfile(fullchain_file)):
            with open(fullchain_file, 'r') as openfile:
                fullchain = openfile.read().rstrip('\n')
            return fullchain
        else:
            print "Could not find file: {0}".format(fullchain_file)
            return None

    def get_rancher_certificate_servers(self):
        '''
        Retrieve a list of CN's of certificates in the Rancher UI.
        '''
        returned_json = self.get_certificate()
        cns = []
        for certificate in returned_json:
            if(certificate['state'] == "active"):
                print "CN: {0} is active".format(certificate['CN'])
                cns.append(certificate['CN'])
        return cns

    def acme_challenge_failed(self, host):
        self.acme_challenge_write()
        url = "http://{0}/.well-known/acme-challenge/".format(host)
        try:
            r = requests.get(url, headers=self.headers, timeout=60)
        except:
            return True
        if r.content.startswith(self.internal_challenge_value):
            print "ACME challenge pre-test succeeded, using certbot to get certificate for " + host
            return False
        else:
            print "ACME challenge pre-test failed, check that " + host + " is routed correctly."
            return True

    def get_dynamic_domains(self):
        if not DYNAMIC_CONFIG:
            return Set()

        url = 'http://rancher-metadata.rancher.internal/2015-12-19/containers'
        try:
            r = requests.get(url, headers=self.headers_want_json, timeout=60)
        except:
            print "Failed to fetch rancher metadata"
            return []
        try:
            parsed_json = r.json()
        except:
            print "Failed to parse rancher metadata JSON"
            return []

        host_list = Set()
        for service in parsed_json:
            if 'labels' in service and 'com.danieldent.rancher-lets-encrypt.hosts' in service['labels']:
                for host in service['labels']['com.danieldent.rancher-lets-encrypt.hosts'].encode('ascii', 'ignore').split(','):
                    host_list.add(host)

        return host_list

if __name__ == "__main__":
    service = RancherService()
    service.initialize()
    try:
        service.cert_manager_loop()
    except requests.exceptions.Timeout:
        print "A request timed out, re-starting loop"
        pass

