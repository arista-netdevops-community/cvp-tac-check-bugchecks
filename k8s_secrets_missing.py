from bugchecks.bug import Bug
import lib.return_codes as code

class k8s_secrets_missing(Bug):
  def __init__(self):
    super(k8s_secrets_missing, self).__init__()

    self.check_secrets = ['ambassador-tls-origin']

  def scan(self):
    value = code.OK
    message = None
    missing_secrets = []
    available_secrets = []

    if self.is_using_local_logs():
      value = code.UNSUPPORTED
    else:
      secrets = self.get_k8s_resources(resource_type='secret')
      for secret in secrets:
        available_secrets.append(secret)
      if not set(self.check_secrets).issubset(available_secrets):
        missing_secrets = list(set(self.check_secrets).difference(available_secrets))
        value = code.ERROR
        message = ', '.join(missing_secrets)

    self.set_status(value, message, missing_secrets)
    return(value)

  def patch(self):
    value = code.OK
    message = None

    self.debug("Resetting ambassador...", code.LOG_INFO)
    self.cvpi(action='reset', services=['ambassador'])
    self.cvpi(action='init', services=['ambassador'])

    self.debug("Starting CVP components", code.LOG_INFO)
    self.cvpi(action='start')

    return(value, message)
