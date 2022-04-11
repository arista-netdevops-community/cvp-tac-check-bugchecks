from bugchecks.bug import Bug
import lib.return_codes as code

import re
import yaml

class cvpi_resources(Bug):
  def __init__(self):
    super(cvpi_resources, self).__init__()

  def __scan_logs(self):
    config = {}
    keys = [
        'bandwidth',
        'cpu',
        'diskthroughput',
        'memory',
        'ntp',
        'storage',
        'time'
        ]
    for key in keys:
      if key == 'cpu':
        if self.get_node_role() == 'primary':
          index = 4
        elif self.get_node_role() == 'secondary':
          index = 6
        elif self.get_node_role() == 'tertiary':
          index = 8
        file = self.read_file(self.local_directory(directory_type='commands')+'/resources_cpu')
        for line in file:
          if 'CPU Count' in line:
            value = int(self.__remove_colorcodes(line).split()[index])
      elif key == 'memory':
        v = {}
        file = self.read_file(self.local_directory(directory_type='commands')+'/free_m')
        for line in file:
          if 'Mem:' in line:
            v['available'] = int(self.__remove_colorcodes(line).split()[6])
            v['total'] = int(self.__remove_colorcodes(line).split()[1])
        value = v
      elif key == 'ntp':
        if self.get_node_role() == 'primary':
          index = 4
        elif self.get_node_role() == 'secondary':
          index = 6
        elif self.get_node_role() == 'tertiary':
          index = 8
        file = self.read_file(self.local_directory(directory_type='commands')+'/resources_ntp')
        for line in file:
          if 'NTP Status' in line:
            value = self.__remove_colorcodes(line).split()[index]
      elif key == 'storage':
        if self.get_node_role() == 'primary':
          index_available = 7
          index_total = 6
        elif self.get_node_role() == 'secondary':
          index_available = 10
          index_total = 9
        elif self.get_node_role() == 'tertiary':
          index_available = 13
          index_total = 12
        if self.cvp_is('<', '2020.2.0'):
          index_available = index_available-1
          index_total = index_total-1
        elif self.cvp_is('<', '2021.0.0'):
          index_available = index_available+1
          index_total = index_total+1
        v = {}
        file = self.read_file(self.local_directory(directory_type='commands')+'/resources_storage')
        for line in file:
          if 'Size of /data' in line:              
            try:
              v['available'] = float(re.sub(r'[()a-zA-Z]+', '', self.__remove_colorcodes(line).split()[index_available]))*1024
              v['total'] = float(re.sub(r'[()a-zA-Z]+', '', self.__remove_colorcodes(line).split()[index_total]))*1024
            except ValueError:
              self.debug("Error parsing line: " + line, code.LOG_ERROR)
              self.debug("CVP Version: " + self.config['version'], code.LOG_DEBUG)
              self.debug("Available space index: " + index_available, code.LOG_DEBUG)
              self.debug("Total space index: " + index_total, code.LOG_DEBUG)
              raise
        value = v
      elif key == 'time':
        if self.get_node_role() == 'primary':
          index = 4
        elif self.get_node_role() == 'secondary':
          index = 6
        elif self.get_node_role() == 'tertiary':
          index = 8
        file = self.read_file(self.local_directory(directory_type='commands')+'/resources_time')
        for line in file:
          if 'System Time' in line:
            value = self.__remove_colorcodes(line).split()[index]
      elif key == 'diskthroughput':
        if self.get_node_role() == 'primary':
          index = 6
        elif self.get_node_role() == 'secondary':
          index = 9
        elif self.get_node_role() == 'tertiary':
          index = 12
        value = code.UNSUPPORTED
      elif key == 'bandwidth':
        value = code.UNAVAILABLE
      else:
        self.debug("FIXME: " + key, code.LOG_DEBUG)
        value = code.UNAVAILABLE
      config[key] = value

    return([code.OK, config])

  def __scan_node(self):
    config = {}
    resources = self.run_command("cvpi resources --yaml", silence_cvpi_warning=True, cacheable=True).stdout
    resources = yaml.safe_load('\n'.join(resources))
    if resources:
      for resource in resources:
        if resource['node'] == self.get_node_role():
          value = resource['result']['stdout']
          value = yaml.safe_load(value)
          key = value['cname']
          if key == 'bandwidth':
            value = value[key]
          elif key == 'cpu':
            value = int(value[key]['total'])
          elif key == 'diskthroughput':
            value = float(value[key]['disktpt'])
          elif key == 'memory':
            v = {}
            v['available'] = value[key]['avail']
            v['total'] = value[key]['total']
            value = v
          elif key == 'networklatency':
            value = value[key]['latency']
          elif key == 'ntp':
            value = value[key]['sync']
          elif key == 'storage':
            v = {}
            v['available'] = value[key]['avail']
            v['total'] = value[key]['total']
            value = v
          elif key == 'time':
            value = value[key]['time']
          else:
            print("FIXME: " + key)

          config[key] = value
    return([code.OK, config])

  def __remove_colorcodes(self, input):
    colorcodes = ['\x1b[1m', '\x1b[0m']
    for code in colorcodes:
      input = input.replace(code, '')
    return(input)

  def scan(self):
    value = code.OK
    message = None

    if self.is_using_local_logs():
      self.debug("Scanning debug logs", code.LOG_DEBUG)
      value, cvpi_config = self.__scan_logs()
    else:
      self.debug("Performing live scan", code.LOG_DEBUG)
      value, cvpi_config = self.__scan_node()

    self.set_status(value, message, cvpi_config)
    return(value)
