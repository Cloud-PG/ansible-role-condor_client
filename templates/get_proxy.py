#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import print_function

import json
import logging
import os
import subprocess
import sys
import time
from StringIO import StringIO

import requests
from urllib3._collections import HTTPHeaderDict

import pycurl

if sys.version_info.major == 2:
    from urlparse import urlsplit
else:
    from urllib.parse import urlsplit

class ProxyManager(object):

    """Manager of tokens."""

    def __init__(self, cfg, cache_manager=None):
        # Get all environment variables
        self.iam_token = cfg.get('IAM_TOKEN')
        self.iam_client_id = cfg.get('IAM_CLIENT_ID')
        self.iam_client_secret = cfg.get('IAM_CLIENT_SECRET')
        self.audience = cfg.get('AUDIENCE')
        # CACHE
        self.cache_dir = '/tmp'

        self.iam_endpoint = cfg.get('IAM_ENDPOINT')
        self.iam_token_endpoint = self.iam_endpoint + 'token'
        self.iam_credential_endpoint = cfg.get('CREDENTIAL_ENDPOINT')
 
        self.tts_url = cfg.get('TTS')

        self.user_cert    = "{}/usercert.crt".format(self.cache_dir)
        self.user_key     = "{}/userkey.key".format(self.cache_dir)
        self.user_passwd  = "{}/userpasswd.txt".format(self.cache_dir)
        self.user_proxy   = "{}/x509up_u%s".format(self.cache_dir)%(os.geteuid())


    def get_certificate(self):
        """Retrieve the certificate.

        :returns: The given tts token
        :raises requests.exceptions: possible on redirect
        :raises pycurl.exceptions: during the call of iam credential endpoint

        .. todo::
            Manage controls (gestisci controlli)

        """
        data = json.dumps({"service_id": "x509"})

        logging.debug("Create headers and buffers")
        headers = StringIO()
        buffers = StringIO()

        logging.debug("Prepare CURL")
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, bytes(self.iam_credential_endpoint))
        curl.setopt(pycurl.HTTPHEADER, [
            'Authorization: Bearer {}'.format(
                str(self.exchanged_token).split('\n', 1)[0]),
            'Content-Type: application/json'
        ])
        curl.setopt(pycurl.POST, 1)
        curl.setopt(pycurl.POSTFIELDS, data)
        curl.setopt(curl.WRITEFUNCTION, buffers.write)
        curl.setopt(curl.HEADERFUNCTION, headers.write)
        curl.setopt(curl.VERBOSE, False)
  
        try:
            logging.debug("Perform CURL call")
            curl.perform()
            status = curl.getinfo(curl.RESPONSE_CODE)
            logging.debug("Result status: %s", status)
            logging.debug("Close CURL")
            curl.close()
            logging.debug("Get body content")
            body = buffers.getvalue()
            logging.debug("Body: %s", body)
            if str(status) != "303":
                logging.error(
                    "On 'get redirected with curl': http error: %s", str(status))
                return False
        except pycurl.error as error:
            errno, errstr = error
            logging.error('A pycurl error n. %s occurred: %s', errno, errstr)
            return False

        logging.debug("Manage redirect")
        for item in headers.getvalue().split("\n"):
            if "location" in item:
                # Example item
                #   "location: https://watts-dev.data.kit.edu/api/v2/iam/credential_data/xxx"
                logging.debug("Item url: %s", item)
                url_path = urlsplit(item.strip().split()[1]).path
                redirect = self.tts_url + url_path
                logging.debug("Redirect location: %s", redirect)

                headers = {'Authorization': 'Bearer ' +
                           self.exchanged_token.strip()}
                response = requests.get(redirect, headers=headers)

                try:
                    response.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    # Whoops it wasn't a 200
                    logging.error(
                        "Error in get certificate redirect: %s", str(err))
                    return False

                with open('/tmp/output.json', 'w') as outf:
                    outf.write(response.content)

                cur_certificate = json.loads(response.content)
                cert_id = cur_certificate['credential']['id']
                logging.debug("Certificate id: '%s'", cert_id)
                if self.revoke_cert(cert_id):
                    logging.debug("Certificate '%s' revoked", cert_id)
                else:
                    logging.error("Certificate '%s' NOT REVOKED", cert_id)
            else:
                #logging.error("No location in redirect response")
                pass

        return True

    def revoke_cert(self, cert_id):
        """Revoke a certificate.
        
        :param cert_id: str
        :returns: bool, the end status of the operation
        :raises requests.exceptions: possible on redirect
        :raises pycurl.exceptions: during the call of iam credential endpoint

        """
        logging.debug("Create buffers")
        buffers = StringIO()

        logging.debug("Prepare CURL to revoke cert '%s'", cert_id)
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, bytes(
            "{}/{}".format(self.iam_credential_endpoint, cert_id))
        )
        curl.setopt(pycurl.HTTPHEADER, [
            'Authorization: Bearer {}'.format(
                str(self.exchanged_token).split('\n', 1)[0]),
        ])
        curl.setopt(pycurl.CUSTOMREQUEST, "DELETE")
        curl.setopt(curl.WRITEFUNCTION, buffers.write)
        curl.setopt(curl.VERBOSE, False)

        try:
            logging.debug("Perform CURL call to DELETE '%s'", cert_id)
            curl.perform()
            status = curl.getinfo(curl.RESPONSE_CODE)
            logging.debug("Result status: %s", status)
            logging.debug("Close CURL")
            curl.close()
            logging.debug("Get body content")
            body = buffers.getvalue()
            logging.debug("Body: %s", body)
            body_dict = json.loads(body)
            if body_dict['result'] != "ok":
                return False
        except pycurl.error as error:
            errno, errstr = error
            logging.error(
                'A pycurl error n. %s occurred on DELETE: %s', errno, errstr)
            return False
        return True

    def get_exchange_token(self):
        """Retrieve the access token.

        Exchange the access token with the given client id and secret.
        The refresh token in cached and the exchange token is kept in memory.

        .. todo::
            Add controls (aggiungi controlli)

        """

        logging.debug("Prepare header")

        data = HTTPHeaderDict()
        data.add('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange')
        data.add('audience', self.audience)
        data.add('subject_token', self.iam_token)
        data.add('scope', 'openid profile offline_access')

        logging.debug("Call get exchanged token with data: '%s'", str(data))

        response = requests.post(self.iam_token_endpoint, data=data, auth=(
            self.iam_client_id, self.iam_client_secret), verify=True)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            # Whoops it wasn't a 200
            logging.error("Error in get exchange token: %s", err)
            return response.status_code

        result = json.loads(response.content)
        logging.debug("Result: %s", result)

        return result["access_token"]

    def get_tts_data(self, exchange=False):
        """Get TTS data using a lock procedure.

        Phases:
            - get lock
            - retrieve_tts_data
            - release lock

        :param exchange: Bool (Default value = False)

        """
        if self.get_certificate():
            logging.debug("Load json and prepare objects")
            with open('/tmp/output.json') as tts_data_file:
                tts_data = json.load(tts_data_file)

            with open(self.user_cert, 'w+') as cur_file:
                cur_file.write(
                    str(tts_data['credential']['entries'][0]['value']))

            with open(self.user_key, 'w+') as cur_file:
                cur_file.write(
                    str(tts_data['credential']['entries'][1]['value']))

            with open(self.user_passwd, 'w+') as cur_file:
                cur_file.write(
                    str(tts_data['credential']['entries'][2]['value']))

            try:
                logging.debug("Change user key mod")
                os.chmod(self.user_key, 0o600)
                os.chmod(self.user_cert, 0o644)
            except OSError as err:
                logging.error(
                    "Permission denied to chmod passwd file: %s", err)
                return False

            return True

        return False

    def generate_proxy(self):
        """Generates proxy with grid-proxy-init only if there are not errors."""
        self.exchanged_token = self.get_exchange_token()
        if self.get_tts_data():
            logging.debug("Generating proxy for %s", self.exchanged_token)

            command = "grid-proxy-init -valid 160:00 -key {} -cert {} -out {} -pwstdin ".format(
                self.user_key, self.user_cert, self.user_proxy
            )
            with open(self.user_passwd) as my_stdin:
                my_passwd = my_stdin.read()
            proxy_init = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )

            logging.debug("Execute proxy")
            proxy_out, proxy_err = proxy_init.communicate(input=my_passwd)

            logging.debug("Proxy result: %s", proxy_init.returncode)
            if proxy_init.returncode > 0:
                logging.error("grid-proxy-init failed for token %s",
                              self.exchanged_token)
                logging.error("grid-proxy-init failed stdout %s", proxy_out)
                logging.error("grid-proxy-init failed stderr %s", proxy_err)
            else:
                return self.user_proxy
        else:
            logging.error("Error occured in check_tts_data!")


"""Execute the get_proxy routine."""

configuration = {
    'CREDENTIAL_ENDPOINT' : 'https://dodas-tts.cloud.cnaf.infn.it/api/v2/iam/credential',
    'IAM_ENDPOINT':'https://dodas-iam.cloud.cnaf.infn.it/',
    'TTS':'https://dodas-tts.cloud.cnaf.infn.it',
    'IAM_CLIENT_ID': "{{ iam.client_id }}",
    'IAM_CLIENT_SECRET': "{{ iam.client_secret }}",
    'AUDIENCE' : 'https://dodas-tts.cloud.cnaf.infn.it',
    'IAM_TOKEN': "{{ iam.token }}" }

proxy_manager = ProxyManager(configuration)
proxy_file = proxy_manager.generate_proxy()
print("\n Created proxy in %s \n"%proxy_file)
