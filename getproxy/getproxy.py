#! /usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import, division, \
    print_function

import os
import json
import time
import copy
import signal
import logging

import requests
import geoip2.database

from threading import Thread
from queue import Queue, Empty

from .utils import signal_name, load_object


logger = logging.getLogger(__name__)


class GetProxy(object):
    base_dir = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, input_proxies=[], only_https=False,
                 max_response_time=None, only_anonimous=False,
                 n_threads=200):
        self.plugins = []
        self.web_proxies = []
        self.valid_proxies = []
        self.input_proxies = input_proxies
        self.proxies_hash = {}
        self.only_https = only_https
        self.max_response_time = max_response_time
        self.only_anonimous = only_anonimous
        self.origin_ip = None
        self.geoip_reader = None
        self.n_threads = n_threads

    def _collect_result(self):
        for plugin in self.plugins:
            if not plugin.result:
                continue

            self.web_proxies.extend(plugin.result)

    def _validate_proxy(self, proxy, scheme='http'):
        country = proxy.get('country')
        host = proxy.get('host')
        port = proxy.get('port')

        proxy_hash = '%s://%s:%s' % (scheme, host, port)
        if proxy_hash in self.proxies_hash:
            return

        self.proxies_hash[proxy_hash] = True
        request_proxies = {
            scheme: "%s:%s" % (host, port)
        }

        request_begin = time.time()
        try:
            response_json = requests.get(
                "%s://httpbin.org/get?show_env=1&cur=%s" % (scheme,
                                                            request_begin),
                proxies=request_proxies,
                timeout=5
            ).json()
        except:
            return

        request_end = time.time()
        response_time = round(request_end - request_begin, 2)

        if self.max_response_time:
            if response_time > self.max_response_time:
                return

        if str(request_begin) != response_json.get('args', {}).get('cur', ''):
            return

        anonymity = self._check_proxy_anonymity(response_json)
        if self.only_anonimous and anonymity == 'transparent':
            return
        country = country or self.geoip_reader.country(host).country.iso_code
        export_address = self._check_export_address(response_json)

        return {
            "type": scheme,
            "host": host,
            "export_address": export_address,
            "port": port,
            "anonymity": anonymity,
            "country": country,
            "response_time": response_time,
            "from": proxy.get('from')
        }

    def validate_proxy(self, queue, valid_proxies):
        while True:
            try:
                proxy = queue.get(timeout=10)
                logger.debug("validating proxy %s", proxy)
                res = self._validate_proxy(proxy)
                if res:
                    valid_proxies.append(res)
                queue.task_done()
            except Empty:
                return

    def _validate_proxy_list(self, proxies, timeout=300):
        valid_proxies = []

        queue = Queue()
        for proxy in proxies:
            queue.put(proxy)

        self.threads = [Thread(target=self.validate_proxy,
                               name="ProxyValidator " + str(x),
                               args=(queue, valid_proxies))
                        for x in range(self.n_threads)]

        for thread in self.threads:
            thread.setDaemon(True)
            thread.start()

        queue.join()

        return valid_proxies

    def _check_proxy_anonymity(self, response):
        via = response.get('headers', {}).get('Via', '')

        if self.origin_ip in json.dumps(response):
            return 'transparent'
        elif via and via != "1.1 vegur":
            return 'anonymous'
        else:
            return 'high_anonymous'

    def _check_export_address(self, response):
        origin = response.get('origin', '').split(', ')
        if self.origin_ip in origin:
            origin.remove(self.origin_ip)
        return origin

    def _request_force_stop(self, signum, _):
        logger.warning("[-] Cold shut down")

        raise SystemExit()

    def _request_stop(self, signum, _):
        logger.debug("Got signal %s" % signal_name(signum))

        signal.signal(signal.SIGINT, self._request_force_stop)
        signal.signal(signal.SIGTERM, self._request_force_stop)

    def init(self):
        logger.debug("[*] Init")
        signal.signal(signal.SIGINT, self._request_stop)
        signal.signal(signal.SIGTERM, self._request_stop)

        rp = requests.get('http://httpbin.org/get')
        self.origin_ip = rp.json().get('origin', '')
        logger.debug("[*] Current Ip Address: %s" % self.origin_ip)

        self.geoip_reader = geoip2.database.Reader(
            os.path.join(self.base_dir, 'data/GeoLite2-Country.mmdb'))

    def validate_input_proxies(self):
        logger.debug("[*] Validate input proxies")
        self.valid_proxies = self._validate_proxy_list(self.input_proxies)
        logger.debug("[*] Check %s input proxies, Got %s valid input proxies" %
                    (len(self.proxies_hash), len(self.valid_proxies)))

    def load_plugins(self):
        logger.debug("[*] Load plugins")
        for plugin_name in os.listdir(os.path.join(self.base_dir, 'plugin')):
            if os.path.splitext(plugin_name)[1] != '.py' or \
                    plugin_name == '__init__.py':
                continue

            try:
                cls = load_object(
                    "getproxy.plugin.%s.Proxy" % os.path.splitext(
                        plugin_name)[0])
            except Exception as e:
                logger.warning("[-] Load Plugin %s error: %s" % (
                    plugin_name, str(e)))
                continue

            inst = cls()
            inst.proxies = copy.deepcopy(self.valid_proxies)
            self.plugins.append(inst)

    def grab_web_proxies(self):
        logger.debug("[*] Grab proxies")

        threads = [Thread(target=plugin.start, args=())
                   for plugin in self.plugins]
        for t in threads:
            t.setDaemon(True)
            t.start()

        for t in threads:
            t.join()

        self._collect_result()

    def validate_web_proxies(self):
        logger.debug("[*] Validate web proxies")
        input_proxies_len = len(self.proxies_hash)

        valid_proxies = self._validate_proxy_list(self.web_proxies)
        self.valid_proxies.extend(valid_proxies)

        output_proxies_len = len(self.proxies_hash) - input_proxies_len

        logger.info(
            "[*] Check %s output proxies, Got %s valid output proxies" %
            (output_proxies_len, len(valid_proxies)))
        logger.info("[*] Check %s proxies, Got %s valid proxies" %
                    (len(self.proxies_hash), len(self.valid_proxies)))

    def start(self):
        self.init()
        self.validate_input_proxies()
        self.load_plugins()
        self.grab_web_proxies()
        self.validate_web_proxies()
        return self.valid_proxies
