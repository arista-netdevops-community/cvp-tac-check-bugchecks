from bugchecks.bug import Bug
import lib.return_codes as code
import os
import time

class cert_expiration(Bug):
  def __init__(self):
    super(cert_expiration, self).__init__()

  def __init_dependencies(self):
    self.debug("Initializing dependencies", code.LOG_DEBUG)
    from bugchecks.cvp_deadline_exceeded import cvp_deadline_exceeded
    from bugchecks.k8s_pods_crashloop import k8s_pods_crashloop
    self.deadline_services = cvp_deadline_exceeded()
    self.deadline_services.configure(
      bootstrap=True,
      connection=self.config['connection'],
      filecache=self.filecache,
      node_config=self.config['node_config'],
      debug_level=self.config['debug']['level'])
    self.deadline_services.scan()

    self.crashloop_pods = k8s_pods_crashloop()
    self.crashloop_pods.configure(
      bootstrap=True,
      connection=self.config['connection'],
      filecache=self.filecache,
      node_config=self.config['node_config'],
      debug_level=self.config['debug']['level'])
    self.crashloop_pods.scan()

  def __scan_logs(self):
    self.__init_dependencies()
    value = code.OK
    services = None
    telltale_services = [
      'aaa',
      'aeris-ccapi',
      'audit',
      'ccapi',
      'cloudmanager',
      'enroll',
      'image',
      'inventory',
      'service-dashboard',
      'service-package',
      'snapshot',
      'ztp'
    ]
    telltale_services.sort()

    crashloop_pods = self.crashloop_pods.get_status(section='extra')
    deadline_services = self.deadline_services.get_status(section='extra')

    if crashloop_pods and set(crashloop_pods).issubset(telltale_services):
      value = code.ERROR
      services = crashloop_pods
    elif crashloop_pods and len(set(crashloop_pods).intersection(telltale_services)) > 0:
      value = code.WARNING
      services = list(set(crashloop_pods).intersection(telltale_services))
    
    if deadline_services and len(set(deadline_services).intersection(telltale_services)) > 0:
      value = code.WARNING
      services = list(set(deadline_services).intersection(telltale_services))

    return([value, services])

  def __scan_node(self):
    certificates = self.certificates()
    check_certs = ['server.crt', 'aerisadmin.crt', 'ca.crt']
    expired, expiring = [], []
    value = code.OK

    for cert in check_certs:
      if not certificates.is_valid(cert):
        expired.append(cert)
      elif certificates.is_close_to_expiration(cert):
        expiring.append(cert)

    if expired:
      value = code.ERROR
    elif expiring:
      value = code.WARNING

    return(value, expired, expiring)

  def scan(self):
    value = code.OK
    message = None
    services = []
    expired = []
    expiring = []
    extra = None

    if self.is_using_local_logs():
      value, services = self.__scan_logs()
    else:
      value, expired, expiring = self.__scan_node()

    if services:
      if value == code.ERROR:
        message = "Related pods in crashloop state: %s" %', '.join(services)
      elif value == code.WARNING:
        message = "Context deadline exceeded messages in related pods: %s" %', '.join(services)
      if self.is_using_local_logs() and (value == code.ERROR or value == code.WARNING):
        message = message + "\n\nDetection from log files may not be reliable. Run the following command on the CVP cluster to confirm:\nfor cert in /cvpi/tls/certs/*.crt; do echo $cert; openssl x509 -noout -text -in $cert|grep -A2 Validity; done"
      self.set_status(value, message, services)
    elif expired or expiring:
      message_expired = None
      message_expiring = None
      extra = {}
      extra['expired'] = expired
      extra['expiring'] = expiring
      if expired and not expiring:
        message = "Expired: %s" %', '.join(expired)
      elif expiring and not expired:
        message = "Expiring: %s" %', '.join(expiring)
      elif expired and expiring:
        message = "Expired: %s / Expiring: %s" %(', '.join(expired), ', '.join(expiring))
      self.set_status(value, message, extra)
    else:
      self.set_status(value, message, extra)

    return(value)

  def patch(self):
    value = code.OK
    message = None
    if self.cvp_is('>=', '2020.0.0'):
      ca = 'ca-init-v1'
    else:
      ca = 'ca'

    self.debug('Stopping CVP services...', code.LOG_WARNING)
    result = self.cvpi(action='stop')
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return(value, message)

    self.debug('Resetting certificates...', code.LOG_WARNING)
    result = self.cvpi(action='start', services=['aeris'])
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return(value, message)

    result = self.run_command('rm -f /cvpi/tls/certs/aerisadmin*')
    if result.exit_code != code.OK:
      value = result.exit_code
      message = result.stderr
      return(value, message)

    result = self.run_command('rm -f /cvpi/tls/certs/server*')
    if result.exit_code != code.OK:
      value = result.exit_code
      message = result.stderr
      return(value, message)

    result = self.cvpi(action='reset', services=[ca])
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return(value, message)

    result = self.cvpi(action='init', services=[ca])
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return(value, message)

    result = self.run_command('su - cvp -c "/cvpi/apps/aeris/bin/init.sh"')
    if result.exit_code != code.OK:
      value = result.exit_code
      message = result.stderr

    self.debug('Starting CVP. This will take a while...', code.LOG_WARNING)
    result = self.cvpi(action='stop', services=['aeris'])
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return(value, message)

    result = self.cvpi(action='start')
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return(value, message)

    return(value, message)
