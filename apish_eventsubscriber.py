import lib.return_codes as code
from bugchecks.bug import Bug
import json

class apish_eventsubscriber(Bug):
  def __init__(self):
    super(apish_eventsubscriber, self).__init__()

  def __scan_logs(self):
    value = code.UNSUPPORTED
    message = "Not supported in this mode"
    
    return(value, message)

  def scan(self):
    value = code.OK
    message = None
    method = 'get'
    dataset = 'cvp'
    path = '/eventSubscriber/ids/'
    action = None
    key = None
    ts = None
    eids = []
    if self.is_using_local_logs():
        self.debug("This information is not available in debug logs", code.LOG_DEBUG)
        value, message = self.__scan_logs()
    else:
      self.debug("Performing live scan", code.LOG_DEBUG)
      output = self.apish(method, dataset, path, action, key, ts)
      self.debug("The output of eventSubscriber scan is: {}".format(output), code.LOG_DEBUG)
      try:
        result = json.loads(output[0])
      except IndexError:
        result = None
      self.debug("The result of eventSubscriber scan is: {}".format(result), code.LOG_DEBUG)
      if result:
        for notif in result['Notifications']:
          eids = eids + list(notif['updates'].keys())
        value = code.ERROR
        if value != code.OK:
          message = ', '.join(eids)
    self.set_status(value, message, eids)
    return(value)


  def patch(self):
    value = code.OK
    message = None
    method = 'publish'
    dataset = 'cvp'
    action = 'delete'
    ts = None
    for eid in self.get_status(section='extra'):
      self.debug("Removing eventSubscriber id %s" %eid, code.LOG_INFO)
      path = '/eventSubscriber/ids/'
      self.apish(method, dataset, path, action, eid, ts)
      path = '/eventSubscriber/ids/' + eid
      self.apish(method, dataset, path, action, eid, ts)

    return(value, message)
