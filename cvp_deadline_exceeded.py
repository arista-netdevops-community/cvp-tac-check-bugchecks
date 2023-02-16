from bugchecks.bug import Bug
import lib.return_codes as code
import re

class cvp_deadline_exceeded(Bug):
  def __init__(self):
    super(cvp_deadline_exceeded, self).__init__()

    self.journalctl_days = '2 days ago'

  def scan(self):
    value = code.OK
    message = None
    services = []
    check_regex = r'event\.go.*Name:\"(.*?)".*DeadlineExceeded'
    diagnostic_files = []

    if self.is_using_local_logs():
      logfile = self.local_directory(directory_type='commands')+'/journalctl'
      journal = self.read_file(logfile)
    else:
      logfile = "journalctl -S '%s' --no-page | grep DeadlineExceeded" %self.journalctl_days
      journal = self.run_command(logfile).stdout

    line_number=1
    for line in journal:
      match = re.search(check_regex, line)
      if match:
        match = match.groups()[0]
        if 'service-' in match:
          service = match.split('-')[1]
        else:
          service = match.split('-')[0]
        diagnostic_entry = "%s:%s" %(logfile, line_number)
        diagnostic_files.append(diagnostic_entry)
        if service not in services:
          services.append(service)
      line_number += 1

    if services:
      value = code.ERROR
      message = ', '.join(services)

    self.set_status(value, message, services, diagnostic_files=diagnostic_files)
    return(value)
