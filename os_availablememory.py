from bugchecks.bug import Bug
import lib.return_codes as code

import re

class os_availablememory(Bug):
  def __init__(self):
    super(os_availablememory, self).__init__()

    self.warn_threshold = 2512
    self.error_threshold = 2048

  def __scan_logs(self):
    available = None

    file = self.local_directory(directory_type='commands')+'/free_m'
    try:
      output = self.read_file(file)
    except Exception as e:
      self.debug("Could not read %s: %s" %(file, e), code.LOG_WARNING)
      output = []

    for line in output:
      if line.startswith('Mem:'):
        available = int(line.split()[6])
    return(available)

  def __scan_node(self):
    available = None
    check_command = "free -m"

    try:
      output = self.run_command(check_command).stdout
    except Exception as e:
      self.debug("Could not run %s: %s" %(check_command, e), code.LOG_WARNING)
      output = []

    for line in output:
      if line.startswith('Mem:'):
        available = int(line.split()[6])
    return(available)

  def scan(self):
    status = code.OK
    message = None
    if self.is_using_local_logs():
      self.debug("Scanning debug logs", code.LOG_DEBUG)
      available = self.__scan_logs()
    else:
      self.debug("Performing live scan", code.LOG_DEBUG)
      available = self.__scan_node()

    if available == None:
      status = code.UNAVAILABLE
    else:
      if available <= self.error_threshold:
        status = code.ERROR
        message = "System running low on RAM: %s. Backups may fail." %available
      elif available <= self.warn_threshold:
        status = code.WARNING
        message = "System running low on RAM: %s." %available

    self.set_status(status, message, available)
    return(status)
