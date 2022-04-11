from bugchecks.bug import Bug
import lib.return_codes as code
from bugchecks.cvpi_status import cvpi_status

class cvp_running_components(cvpi_status):
  def __init__(self):
    super(cvp_running_components, self).__init__()

  def scan(self):
    value = code.OK
    message = None
    notrunning = []

    component_ok_status = 0
    component_disabled_status = 6

    self.debug("Running parent's scan()", code.LOG_DEBUG )
    super(cvp_running_components, self).scan()

    self.debug("Getting parent's status", code.LOG_DEBUG)
    status_check = super(cvp_running_components, self).get_status(section='code')
    
    if status_check == code.OK:
      components = super(cvp_running_components, self).get_status(section='extra')['component']
      for component in components:
        if components[component] != component_ok_status and components[component] != component_disabled_status:
          notrunning.append(component)

      if notrunning:
        value = code.ERROR
        message = ', '.join(notrunning)
    else:
      value = status_check
      message = super(cvp_running_components, self).get_status(section='message')

    self.set_status(value, message, notrunning)
    return(value)
