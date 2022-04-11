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

    if self.is_using_local_logs():
      journal = self.read_file(self.local_directory(directory_type='commands')+'/journalctl')
    else:
      journal = self.run_command("journalctl -S '%s' --no-page | grep DeadlineExceeded" %self.journalctl_days).stdout

    for line in journal:
      match = re.search(check_regex, line)
      if match:
        match = match.groups()[0]
        if 'service-' in match:
          service = match.split('-')[1]
        else:
          service = match.split('-')[0]
        if service not in services:
          services.append(service)

    if services:
      value = code.ERROR
      message = ', '.join(services)

    self.set_status(value, message, services)
    return(value)
