import lib.return_codes as code
from bugchecks.cvpi_resources import cvpi_resources

class os_ntpsync(cvpi_resources):
  def __init__(self):
    super(os_ntpsync, self).__init__()

  def scan(self):
    value = code.OK
    message = None

    self.debug("Running parent's scan()", code.LOG_DEBUG )
    super(os_ntpsync, self).scan()

    self.debug("Getting parent's status", code.LOG_DEBUG)
    ntp_status = super(os_ntpsync, self).get_status(section='extra')['ntp']

    if ntp_status != 'synchronized':
      value = code.ERROR
      message = str(ntp_status)

    self.set_status(value, message, ntp_status)
    return(value)
