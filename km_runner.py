#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runner for kindermon.py"""

__appname__ = "km_runner"
__author__ = "Kingshuk Dasgupta (rextrebat/kdasgupta)"
__version__ = "0.0pre0"

import kindermon
import configparser
import logging

WEEKDAYS = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Kindermon Runner.')
    parser.add_argument('--all', dest='all', action='store_true',
                        help='All Devices. Overrides --device')
    parser.add_argument('--block', dest='block', action='store_true',
                        help='Block specified device')
    parser.add_argument('--unblock', dest='unblock', action='store_true',
                        help='unblock specified device')
    parser.add_argument('--device', dest='device', action='store',
                        help='Block/Unblock specified device')
    parser.add_argument('--auto', dest='auto', action='store_true',
                        help='Automatic Sleep or Block Devices')

    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read('kindermon.conf')

    username = config.get('credentials', 'username')
    password = config.get('credentials', 'password')

    devices = config['devices']

    if args.all:
        device_list = [devices[k] for k in devices]
    else:
        if args.device:
            device_list = [devices[args.device]]

    kindermon.login(username, password)

    for device in device_list:
        if args.block:
            kindermon.block(device)
        if args.unblock:
            kindermon.unblock(device)

    kindermon.logout()
