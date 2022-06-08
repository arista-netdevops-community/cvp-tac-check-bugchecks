from bugchecks.bug import Bug
import lib.return_codes as code
import os
import time

class cert_issues(Bug):
  def __init__(self):
    super(cert_issues, self).__init__()

  def __init_dependencies(self):
    self.debug("Initializing dependencies", code.LOG_DEBUG)
    from bugchecks.cvp_deadline_exceeded import cvp_deadline_exceeded
    from bugchecks.k8s_pods_crashloop import k8s_pods_crashloop
    self.service_auth_error_message = 'rpc error: code = Unauthenticated desc = not authenticated'
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
    services = []
    service_auth_errors = None
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

    logfile = self.local_directory('commands')+'/journalctl'
    service_auth_errors = self.read_file(logfile, grep=self.service_auth_error_message)
    if service_auth_errors and value == code.OK:
      value = code.INFO

    return([value, services, service_auth_errors])

  def __scan_node(self):
    certificates = self.certificates()
    check_certs = certificates.list()
    value = code.OK
    failed_certs = []
    failure_reason = []

    for cert in check_certs:
      if cert == 'saml.crt':
        validation = certificates.is_valid(cert, validate_chain=False)
      else:
        validation = certificates.is_valid(cert)
      if not validation.result:
        if (validation.failed == ['close to expiration (k8s)'] or validation.failed == ['close to expiration (filesystem)']) and value != code.ERROR:
          value = code.WARNING
        else:
          value = code.ERROR
        if cert not in failed_certs:
          failed_certs.append(cert)
        failure_reason.append("%s: %s" %(cert, ', '.join(validation.failed)))

    return(value, failed_certs, failure_reason)

  def scan(self):
    value = code.OK
    message = None
    services = []
    service_auth_errors = None
    failed_certs = []
    extra = None

    if self.is_using_local_logs():
      value, services, service_auth_errors = self.__scan_logs()
    else:
      value, failed_certs, failure_reason = self.__scan_node()

    if services:
      if value == code.ERROR:
        message = "Related pods in crashloop state: %s" %', '.join(services)
      elif value == code.WARNING:
        message = "Context deadline exceeded messages in related pods: %s" %', '.join(services)

      if self.is_using_local_logs():
        if value == code.ERROR or value == code.WARNING:
          message = message + "\n\nDetection from log files may not be reliable. Run the following command on the CVP cluster to confirm:\n# for cert in /cvpi/tls/certs/*.crt; do echo $cert; openssl x509 -noout -text -in $cert|grep -A2 Validity; done"
      extra = services

    if failed_certs:
      message = "| ".join(failure_reason)
      extra = failed_certs

    if service_auth_errors:
      message_template = "Service authentication errors found in logs. THIS MIGHT NOT BE AN ISSUE. To confirm results from the debug bundle run the following commands on the CVP server:\n\n# kubectl get secret ambassador-tls-origin -o 'go-template={{ index .data \"tls.crt\"}}'|base64 -d|diff /cvpi/tls/certs/ambassador.crt -\n# kubectl get secret ambassador-tls-origin -o 'go-template={{ index .data \"tls.crt\"}}'|base64 -d|openssl x509 -noout -enddate\n"
      if message:
        message = message + "\n\n----------\n" + message_template
      else:
        message = message_template

    self.set_status(value, message, extra)

    return(value)

  def __patch_ambassador(self):
    value = code.OK
    message = None

    self.debug("Resetting ambassador...", code.LOG_INFO)
    failed = self.cvpi(action='reset', services=['ambassador']).failed
    if not failed:
      self.debug("Initializing ambassador...", code.LOG_INFO)
      failed = self.cvpi(action='init', services=['ambassador']).failed
      if failed:
        message = "Ambassador init failed"
        value = code.WARNING
    else:
      message = "Ambassador reset failed"
      value = code.WARNING
    
    if value != code.OK:
      return value, message

    if self.get_cluster_mode() == 'multinode':
      self.debug("Copying certificates to all nodes...", code.LOG_INFO)
      copy_to = ['secondary', 'tertiary']
      for node in copy_to:
        self.debug("  %s" %node, code.LOG_INFO)
        self.run_command("su - cvp -c \"scp -3 -pr $PRIMARY_HOST_IP:/cvpi/tls/certs/amb* $%s_HOST_IP:/cvpi/tls/certs\"" %node.upper())
    return value, message

  def __patch_certs(self, ca):
    self.debug('Stopping CVP services...', code.LOG_WARNING)
    result = self.cvpi(action='stop')
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return value, message

    self.debug('Resetting certificates...', code.LOG_WARNING)
    result = self.cvpi(action='start', services=['aeris'])
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return value, message

    result = self.run_command('rm -f /cvpi/tls/certs/aerisadmin*')
    if result.exit_code != code.OK:
      value = result.exit_code
      message = result.stderr
      return value, message

    result = self.run_command('rm -f /cvpi/tls/certs/server*')
    if result.exit_code != code.OK:
      value = result.exit_code
      message = result.stderr
      return value, message

    result = self.cvpi(action='reset', services=[ca])
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return value, message

    result = self.cvpi(action='init', services=[ca])
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return value, message

    result = self.run_command('su - cvp -c "/cvpi/apps/aeris/bin/init.sh"')
    if result.exit_code != code.OK:
      value = result.exit_code
      message = result.stderr
      return value, message

    result = self.cvpi(action='stop', services=['aeris'])
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return value, message

    return value, message

  def patch(self):
    value = code.OK
    message = None
    if self.cvp_is('>=', '2020.0.0'):
      ca = 'ca-init-v1'
    else:
      ca = 'ca'

    failed_certs = self.get_status(section='extra')
    if failed_certs != ['ambassador.crt']:
      value, message = self.__patch_certs(ca=ca)

    if value == code.OK and (failed_certs == ['ambassador.crt'] or 'ambassador.crt' in failed_certs):
      value, message = self.__patch_ambassador()

    if value == code.OK:
      self.debug('Starting CVP. This will take a while...', code.LOG_WARNING)
      result = self.cvpi(action='start')
      if result.failed:
        value = code.ERROR
        message = "Actions failed: %s" %result.failed
        return(value, message)

    return(value, message)
