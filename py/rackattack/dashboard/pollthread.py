from rackattack.dashboard import tojs
from rackattack import clientfactory
import time
import logging
import traceback
import threading
import subprocess


class PollThread(threading.Thread):
    _INTERVAL = 5
    SERVERS_WARNING_SEARCH_INTERVAL = 60 * 5
    CONNECTION_STRING_PATTERN = "tcp://<ADDR>:1014@@amqp://guest:guest@<ADDR>:1013/%2F@@http://<ADDR>:1016"

    def __init__(self, name, host):
        threading.Thread.__init__(self)
        self.daemon = True
        self._name = name
        self._host = host
        self._lastWarningSearchInterval = 0
        self._warningSearchCounter = 0
        self._warnings = None
        threading.Thread.start(self)

    def run(self):
        while True:
            try:
                connectionString = self.CONNECTION_STRING_PATTERN.replace("<ADDR>", self._host)
                client = clientfactory.factory(connectionString)
            except:
                logging.error("Unable to create ipc client to %(host)s", dict(host=self._host))
                time.sleep(self._INTERVAL)
                continue
            try:
                self._work(client)
            except:
                time.sleep(self._INTERVAL)
            finally:
                client.close()

    def _getServersFromCMD(self, cmd):
        try:
            servers = subprocess.check_output(cmd, shell=True, close_fds=True)
        except:
            logging.error("Could not execute command:")
            logging.error(cmd)
            logging.error(traceback.format_exc())
            return
        return servers

    def _searchByCmdWithServerIdInOutput(self, hosts, cmd, message):
        servers = self._getServersFromCMD(cmd)
        for serverID in servers.splitlines():
            server = [host for host in hosts if host["id"] == serverID]
            if server:
                self._warnings.setdefault(serverID, list()).append(message)

    def _searchForBadSSDs(self, hosts):
        cmd = 'grep "Did not find any" /var/lib/rackattackphysical/seriallogs/ -rn  -l | sort -h | cut -d' \
              '"/" -f 6  | cut -d "-" -f 1-2'
        self._searchByCmdWithServerIdInOutput(hosts, cmd, "Bad/Unrecognized SSD")

    def _searchForIOErrors(self, hosts):
        cmd = 'grep "failed command:" /var/lib/rackattackphysical/seriallogs/ -rn  -l | sort -h | cut -d ' \
              '"/" -f 6  | cut -d "-" -f 1-2'
        self._searchByCmdWithServerIdInOutput(hosts, cmd, "Disk I/O errors detected")

    def _searchForBadBMCs(self, hosts):
        cmd = 'grep "Unable to establish IPMI" /var/lib/rackattackphysical/seriallogs/ -rn  -l | sort -h | cut -d ' \
              '"/" -f 6  | cut -d "-" -f 1-2'
        self._searchByCmdWithServerIdInOutput(hosts, cmd, "Cannot establish an IPMI connection to the BMC")

    def _searchForSlowDisk(self, hosts):
        cmd = 'grep "link is slow to respond" /var/lib/rackattackphysical/seriallogs/ -rn  -l | sort -h | cut -d ' \
              '"/" -f 6  | cut -d "-" -f 1-2'
        self._searchByCmdWithServerIdInOutput(hosts, cmd, "Disk link is slow")

    def _searchServersWithoutInaugurator(self, hosts):
        cmd = 'find `grep "Linux version" -rl /var/lib/rackattackphysical/seriallogs/`  -exec  grep  -H -E -o -c ' \
              ' "Inaugurator stage"  {} \; | grep ":0" | cut -d "/" -f 6 | cut -d "-" -f 1-2'
        message = "Inaugurator boot was not discovered. It is possible that the server does not boot from PXE"
        servers = self._getServersFromCMD(cmd)
        for serverID in servers.splitlines():
            server = [host for host in hosts if host["id"] == serverID]
            if server:
                server = server[0]
                if server["state"] not in ("DETACHED",):
                    self._warnings.setdefault(serverID, list()).append(message)

    def _searchServersWithEmptySOLOutput(self, hosts):
        cmd = 'md5sum /var/lib/rackattackphysical/seriallogs/* | grep 1ace526a4c42a70aed17fdbb15967936 | cut -d ' \
              '"/" -f 6 | cut -d "-" -f 1-2'
        self._searchByCmdWithServerIdInOutput(hosts, cmd, "SOL output is empty")

    def _searchForWarnings(self, hosts):
        self._lastWarningSearchInterval = time.time()
        self._warningSearchCounter += 1
        self._warnings = dict()
        self._searchForBadSSDs(hosts)
        self._searchForIOErrors(hosts)
        self._searchForSlowDisk(hosts)
        self._searchForBadBMCs(hosts)
        self._searchServersWithEmptySOLOutput(hosts)
        if self._warningSearchCounter > 1:
            self._searchServersWithoutInaugurator(hosts)

    def _applyCurrentWarnings(self, hosts):
        for host in hosts:
            if host["id"] in self._warnings:
                host["warnings"] = list(self._warnings[host["id"]])

    def _isItTimeToSearchForWarnings(self):
        if self._warnings is None:
            return True
        return time.time() - self._lastWarningSearchInterval > self.SERVERS_WARNING_SEARCH_INTERVAL

    def _applyWarnings(self, status):
        hosts = status["hosts"]
        if self._isItTimeToSearchForWarnings():
            self._searchForWarnings(hosts)
        self._applyCurrentWarnings(hosts)

    def _work(self, client):
        try:
            while True:
                status = client.call('admin__queryStatus')
                if self._host in ("127.0.0.1", "localhost"):
                    self._applyWarnings(status)
                self._publish(status)
                time.sleep(self._INTERVAL)
        except:
            logging.exception("Unable to query status")

    def _publish(self, status):
        tojs.set('status_%(name)s' % dict(name=self._name), status)
