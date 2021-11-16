#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Monitor Child Devices"""

__appname__ = "kindermon.py"
__author__ = "Kingshuk Dasgupta (rextrebat/kdasgupta)"
__version__ = "0.0pre0"

import sys
import logging
logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
        )

from requests import Request, Session, packages
from requests.packages.urllib3.exceptions import InsecureRequestWarning


unifi_url = 'https://one:443'
site = 'default'
csrf_token = None
cookie_token = None

tracked_headers = ['X-CSRF-TOKEN', 'CONTENT-TYPE', 'CONTENT-LENGTH', 'SET-COOKIE']
session = Session()

def call_unifi(verb, path, payload, parse_response=True, return_error=True):
    global csrf_token, cookie_token, unifi_url, session, tracked_headers

    url = unifi_url + path
    response = None
    try:
        packages.urllib3.disable_warnings(InsecureRequestWarning)
        if verb == 'POST':
            req = Request(verb, url, json=payload)
            if not csrf_token is None:
                logging.debug("Update CSRF Token")
                session.headers.update({'X-CSRF-Token': csrf_token})
            else:
                logging.debug("CSRF Token is None.")
            response = session.send(session.prepare_request(req), verify=False)
            headers = {"Accept": "application/json","Content-Type": "application/json"}
            #req_cookies = session.request.cookies
            resp_cookies = response.cookies
            resp_headers = response.headers
            req_headers = response.request.headers
            for r in req_headers:
                if r.upper() in tracked_headers:
                    logging.debug("REQ HEADER  %s=%s", r, req_headers[r])
            logging.debug("COOKIES <-- %s", resp_cookies)
            for h in resp_headers:
                if h.upper() in tracked_headers:
                    logging.debug("RESP HEADER --> %s: %s", h, resp_headers[h])
                    if h.upper() == 'X-CSRF-TOKEN':
                        csrf_token = resp_headers[h]
                        logging.debug("Token %s=%s saved.", h, csrf_token)
                    elif h.upper() == 'SET-COOKIE':
                        cookie_token = resp_headers[h]
                        logging.debug("Cookie %s=%s saved.", h, cookie_token)
            logging.debug("COOKIE / CSRF TOKEN: %s/%s", cookie_token, csrf_token)
            logging.info("Response status & reason: " + str(response.status_code) + " " + str(response.reason))
        if response.status_code != 200 and response.status_code != 204 and response.status_code !=201 and return_error:
            raise Exception("Error when requesting remote url %s [%s]:%s" % (path,  response.status_code, response.text))
        if parse_response:
            return response.text
        return None
    except:
        print("Unexpected error: ",sys.exc_info()[0])
        sys.exit(2)

def login(user, pwd):
    logging.info("LOGIN")
    payload = {'username': user, 'password': pwd}
    response = call_unifi('POST', '/api/auth/login', payload)

def logout():
    global session
    logging.info("LOGOUT")
    response = call_unifi('POST', '/logout', '')
    session.cookies.clear()

def block(mac):
    global site

    path = '/proxy/network/api/s/{}/cmd/stamgr'.format(site)
    payload = {'cmd': 'block-sta', 'mac': mac}
    response = call_unifi('POST', path, payload)
    logging.info('BLOCK Response: %s', response)

def unblock(mac):
    global site

    path = '/proxy/network/api/s/{}/cmd/stamgr'.format(site)
    payload = {'cmd': 'unblock-sta', 'mac': mac}
    response = call_unifi('POST', path, payload)
    logging.info('UNBLOCK Response: %s', response)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Block/Unblock Child Devices.')
    parser.add_argument('--debug', dest='debug', action='store_true',
                        help='Debug')
    parser.add_argument('--username', dest='username', action='store',
                        help='unifi username')
    parser.add_argument('--password', dest='password', action='store',
                        help='unifi password')
    parser.add_argument('--mac', dest='mac', action='store',
                        help='Device MAC')
    parser.add_argument('--block', dest='block', action='store_true',
                        help='Block specified device')
    parser.add_argument('--unblock', dest='unblock', action='store_true',
                        help='Unblock specified device')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    login(args.username, args.password)

    if args.block:
        block(args.mac.lower())
    if args.unblock:
        unblock(args.mac.lower())

    logout()
    sys.exit(0)
