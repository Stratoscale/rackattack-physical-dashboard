import threading
from rackattack.dashboard import tojs
from rackattack import clientfactory
import time
import logging


class PollThread(threading.Thread):
    _INTERVAL = 5
    CONNECTION_STRING_PATTERN = "tcp://<ADDR>:1014@@amqp://guest:guest@<ADDR>:1013/%2F@@http://<ADDR>:1016"

    def __init__(self, name, host):
        threading.Thread.__init__(self)
        self.daemon = True
        self._name = name
        self._host = host
        threading.Thread.start(self)

    def run(self):
        while True:
            time.sleep(self._INTERVAL)
            try:
                connectionString = self.CONNECTION_STRING_PATTERN.replace("<ADDR>", self._host)
                client = clientfactory.factory(connectionString)
            except:
                logging.error("Unable to create ipc client to %(host)s", dict(host=self._host))
                continue
            try:
                self._work(client)
            finally:
                client.close()

    def _work(self, client):
        try:
            while True:
                time.sleep(self._INTERVAL)
                status = client.call('admin__queryStatus')
                self._publish(status)
        except:
            logging.exception("Unable to query status")

    def _publish(self, status):
        tojs.set('status_%(name)s' % dict(name=self._name), status)
