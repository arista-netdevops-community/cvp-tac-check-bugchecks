from bugchecks.bug import Bug
import lib.return_codes as code

import re

class os_oom(Bug):
  def __init__(self):
    super(os_oom, self).__init__()

    self.system_process_regex = r'Out of memory: Kill[e,d]*? process [^ ]+ \(([^\)]+)\)'
    self.kubelet_process_regex = 'oom event: [^ ]+ ([^ ]+)'
    self.initial_grep_filter = '(memory|oom)'

  def __check_oom(self, line):
    status = code.OK
    process = None
    if 'oom event' in line:
      self.debug("OOM found in line: %s" %line, code.LOG_JEDI)
      status = code.ERROR
      process = re.search(self.kubelet_process_regex, line, re.IGNORECASE)
      if process:
        process = process.groups()[0]
    elif 'Out of memory' in line or 'out of memory' in line:
      self.debug("OOM found in line: %s" %line, code.LOG_JEDI)
      status = code.ERROR
      process = re.search(self.system_process_regex, line, re.IGNORECASE)
      if process:
        process = process.groups()[0]

    return(status, process)

  def __scan_logs(self):
    status = code.OK
    processes = []
    journal = []

    file = self.local_directory(directory_type='logs')+'/kubelet_journalctl'
    try:
      kubelet_journal = self.read_file(file)
    except:
      self.debug("Could not read " + file, code.LOG_WARNING)
      kubelet_journal = []

    file = self.local_directory(directory_type='commands')+'/journalctl'
    try:
      system_journal = self.read_file(file)
    except:
      self.debug("Could not read " + file, code.LOG_WARNING)
      system_journal = []

    for line in kubelet_journal:
      oom, process = self.__check_oom(line)
      if oom != code.OK:
        status = code.ERROR
        if process and process not in processes:
          processes.append(process)
        if 'kubelet' not in journal:
          journal.append('kubelet')

    for line in system_journal:
      oom, process = self.__check_oom(line)
      if oom != code.OK:
        status = code.ERROR
        if process and process not in processes:
          processes.append(process)
        if 'system' not in journal:
          journal.append('system')

    return(status, processes, journal)

  def __scan_node(self):
    status = code.OK
    processes = []
    journal = []
    system_journal = self.run_command("dmesg -T|egrep -i '%s'" %self.initial_grep_filter).stdout

    if system_journal:
      for line in system_journal:
        oom, process = self.__check_oom(line)
        if oom != code.OK:
          status = code.ERROR
          if process and process not in processes:
            processes.append(process)
          if 'system' not in journal:
            journal.append('system')

    return(status, processes, journal)

  def scan(self):
    status = None
    message = None
    processes = None
    if self.is_using_local_logs():
      self.debug("Scanning debug logs", code.LOG_DEBUG)
      status, processes, journal  = self.__scan_logs()
    else:
      self.debug("Performing live scan", code.LOG_DEBUG)
      status, processes, journal = self.__scan_node()

    if status != code.OK:
      message = "OOMs in " + ', '.join(journal) + ": [" + ', '.join(processes) + "]"

    self.set_status(status, message, processes)
    return(status)

