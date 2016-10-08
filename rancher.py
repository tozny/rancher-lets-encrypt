#! /usr/bin/env python2.7

# This python service is reponsible for managing lets encrypt certificates.

import time
import socket
from datetime import datetime
import os
import subprocess
import json
import requests
from OpenSSL import crypto
from requests.auth import HTTPBasicAuth

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
    HOST_CHECK_LOOP_TIME = int(os.environ['HOST_CHECK_LOOP_TIME'])
    HOST_CHECK_PORT = int(os.environ['HOST_CHECK_PORT'])

except KeyError as e:
    print "Could not find an Environment variable set."
    print e


class RancherService:

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
        r = requests.get(url=url, auth=self.auth())
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
            if(server in issuers):
                # we have duplicate certs, so we need to decide which cert is the latest one.
                prev_cert_created = int(issuers[server]['created'])
                next_cert_created = int(cert['createdTS'])
                if(next_cert_created - prev_cert_created < 0):
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
        current_time = int(time.time())
        for certificate in returned_json:
            cn = certificate['CN']
            if(server == cn):
                # found the cert we want to verify
                expires_at = certificate['expiresAt']
                timestamp = datetime.strptime(expires_at, '%a %b %d %H:%M:%S %Z %Y')
                expiry = int(timestamp.strftime("%s"))
                print "Found cert: {0}, Expiry: {1}".format(cn, expiry)
                now = int(time.time())
                if(self.expiring(expiry)):
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
        r = requests.delete(url=url, auth=self.auth())
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

    def loop(self):
        while True:
            self.cert_manager()
            print "Sleeping: {0} seconds...".format(LOOP_TIME)
            time.sleep(LOOP_TIME)

    def cert_manager(self):
        '''
        Check that the server in DOMAINS have certificates in Rancher UI.
        If they do not have a cert, it is a new server, and we need to create a cert.
        If the cert already exists, we should check that it is not going to expire.

        This is where almost all of the logic of the service is for cert issuance, renewal,
        and rancher cert management.
        '''
        servers = self.parse_servernames()
        rancher_cert_servers = self.get_rancher_certificate_servers()
        issuers = self.get_issuer_for_certificates()
        for server in servers:
            if(self.check_cert_files_exist(server)):
                # local copy of cert
                if server not in rancher_cert_servers:
                    # cert not in rancher
                    cert = self.read_cert(server)
                    if(self.local_cert_expired(cert)):
                        # local copy (expired cert)
                        self.create_cert(server)
                        self.post_cert(server)
                    else:
                        # local copy (not expired cert)
                        self.post_cert(server)
                else:
                    # cert in rancher
                    server_cert_issuer = issuers[server]['issuer']
                    if("Fake" in server_cert_issuer and not STAGING):
                        # upgarde staging cert to production
                        print "Upgrading staging cert to production for {0}".format(server)
                        self.create_cert(server)
                        self.post_cert(server)

                    elif("X3" not in server_cert_issuer and not STAGING):
                        # we have a self-signed certificate we should replace with a prod certificate.
                        # this should only happen once on initial rancher install.
                        print "Replacing self-signed certificate: {0}, {1} with production LE cert".format(server, server_cert_issuer)
                        self.create_cert(server)
                        self.post_cert(server)

                    elif(self.rancher_certificate_expired(server)):
                        # rancher cert expired
                        cert = self.read_cert(server)
                        if(self.local_cert_expired(cert)):
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
        # TODO this is incredibly hacky. Certbot is python code so there should be a way to do this without shelling out to the cli certbot tool. (certbot docs suck btw)
        # https://www.metachris.com/2015/12/comparison-of-10-acme-lets-encrypt-clients/#client-simp_le maybe?
        if(STAGING):
            proc = subprocess.Popen(["certbot", "certonly", "--webroot", "-w", CERTBOT_WEBROOT, "--text", "-d", server, "-m", CERTBOT_EMAIL, "--agree-tos", "--renew-by-default", "--staging"], stdout=subprocess.PIPE)
        else:
            # production
            proc = subprocess.Popen(["certbot", "certonly", "--webroot", "-w", CERTBOT_WEBROOT, "--text", "-d", server, "-m", CERTBOT_EMAIL, "--agree-tos", "--renew-by-default"], stdout=subprocess.PIPE)
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
        # check if the cert exists in Rancher first.
        cert_id = self.get_certificate_id(server)
        if(cert_id is not None):
            # the cert exists in rancher, do PUT to update it
            url = "{0}/projects/{1}/certificates/{2}".format(RANCHER_URL, self.get_project_id(), cert_id)
            request_type = requests.put
        else:
            # create the cert for the first time, do POST
            url = "{0}/projects/{1}/certificate".format(RANCHER_URL, self.get_project_id())
            request_type = requests.post

        if(self.check_cert_files_exist(server)):
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

            headers = {'Content-Type': 'application/json'}
            r = request_type(url=url, data=json.dumps(json_structure), headers=headers, auth=self.auth())
            print "HTTP status code: {0}".format(r.status_code)
        else:
            print "Could not find cert files inside post_cert method!"

    def get_project_id(self):
        '''
        get /projects/<id>/certificate
        --> /projects/1a5/certificate
        '''
        url = "{0}/projects".format(RANCHER_URL)
        r = requests.get(url=url, auth=self.auth())
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

    def parse_servernames(self):
        return DOMAINS.split(',')

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

    def hostname_resolves(self, host):
        try:
            socket.gethostbyname(host)
            return True
        except socket.error:
            return False

    def port_open(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        return result is 0

    def check_hostnames_and_ports(self):
        done = False
        while not done:
            # something failed since we are not done
            print "Sleeping during host lookups for {0} seconds".format(HOST_CHECK_LOOP_TIME)
            time.sleep(HOST_CHECK_LOOP_TIME)
            # make sure all hostnames can be resolved and are listening on open ports
            for host in self.parse_servernames():
                if(self.hostname_resolves(host)):
                    print "Hostname: {0} resolves".format(host)
                    if(self.port_open(host, HOST_CHECK_PORT)):
                        print "\tPort {0} open on {1}".format(HOST_CHECK_PORT, host)
                        # check if the /.well-known/acme-challenge/ directory isn't returning a 301 redirect
                        # this is caused by the rancher load balancer not picking up the lets-encrypt service
                        # and not directing traffic to it. Instead the redirection service gets the requests and returns
                        # a 301 redirect. Also, if we get a 503 service unavailable status code there is no lets-encrypt nginx
                        # container working, and we should continue to wait and NOT requests Let's Encrypt certificates yet.
                        url = "http://{0}/.well-known/acme-challenge/:{1}".format(host, HOST_CHECK_PORT)
                        r = requests.get(url, allow_redirects=False)
                        if(r.status_code != 503 and r.status_code != 301):
                            print "\t\tOK, got HTTP status code ({0}) for ({1})".format(r.status_code, host)
                            done = True
                        else:
                            print "\t\tReceived bad HTTP status code ({0}) from ({1})".format(r.status_code, host)
                            done = False
                    else:
                        print "Could not connect to port {0} on host {1}".format(HOST_CHECK_PORT, host)
                        done = False
                else:
                    print "Could not lookup hostname for {0}".format(host)
                    done = False
        print "continuing on to letsencrypt cert provisioning since all hosts seem to be up!"

if __name__ == "__main__":
    service = RancherService()
    service.check_hostnames_and_ports()
    service.loop()
