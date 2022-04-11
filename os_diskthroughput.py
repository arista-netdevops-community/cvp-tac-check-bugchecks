import lib.return_codes as code
from bugchecks.cvpi_resources import cvpi_resources

class os_diskthroughput(cvpi_resources):
  def __init__(self):
    super(os_diskthroughput, self).__init__()

    self.warn_threshold = 50
    self.error_threshold = 40

  def scan(self):
    value = code.OK
    message = None
    throughput = 0

    self.debug("Running parent's scan()", code.LOG_DEBUG )
    super(os_diskthroughput, self).scan()

    self.debug("Getting parent's status", code.LOG_DEBUG)
    throughput = super(os_diskthroughput, self).get_status(section='extra')['diskthroughput']

    if throughput == code.UNSUPPORTED:
      value = code.UNSUPPORTED
      message = "Unsupported in this mode"
    elif throughput == code.UNAVAILABLE:
      message = "Unavailable"
      value = code.WARNING
    else:
      if throughput <= self.error_threshold:
        value = code.ERROR
        message = "/data disk throughput below minimum requirements: %s" %str(throughput)
      elif throughput <= self.warn_threshold:
        value = code.ERROR
        message = "Low /data disk throughput: %s" %str(throughput)

    self.set_status(value, message, throughput)
    return(value)
