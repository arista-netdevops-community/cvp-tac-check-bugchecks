from bugchecks.bug import Bug
import lib.return_codes as code

import yaml

class cvpi_status(Bug):
  def __init__(self):
    super(cvpi_status, self).__init__()

  def __scan_logs(self):
    return([code.UNSUPPORTED, []])

  def __scan_node(self):
    value = code.OK
    status = {}
    if self.get_cluster_mode() == 'singlenode':
      types = ['component', 'systemd']
      component_check_command = "cvpi status --yaml |grep -B9999999 'Systemd Unit Status'|egrep -v '^(Component Status|Systemd Unit Status)$'"
    else:
      types = ['component', 'cluster', 'systemd']
      component_check_command = "cvpi status --yaml |grep -B9999999 'Cluster Status'|egrep -v '^(Component Status|Cluster Status)$'"
      cluster_check_command = "cvpi status --yaml |grep -A9999999 'Cluster Status'|grep -B9999999 'Systemd Unit Status'|egrep -v '^(Component Status|Cluster Status|Systemd Unit Status)$'"
    systemd_check_command = "cvpi status --yaml |grep -A9999999 'Systemd Unit Status'|egrep -v '^(Component Status|Cluster Status|Systemd Unit Status)$'"

    for type in types:
      status[type] = {}
      if type == 'component':
        check_command = component_check_command
      elif type == 'cluster':
        check_command = cluster_check_command
      elif type == 'systemd':
        check_command = systemd_check_command

      components = self.run_command(check_command, silence_cvpi_warning=True, cacheable=True).stdout
      components = yaml.safe_load('\n'.join(components))
      if components:
        for component in components:
          if component['node'] == self.get_node_role():
            name = component['component']
            exitcode = component['result']['exitcode']
            status[type][name] = exitcode

    return([value, status])

  def scan(self):
    value = code.OK
    message = None

    if self.is_using_local_logs():
      self.debug("Scanning debug logs", code.LOG_DEBUG)
      value, components = self.__scan_logs()
    else:
      self.debug("Performing live scan", code.LOG_DEBUG)
      value, components = self.__scan_node()

    self.set_status(value, message, components)
    return(value)
