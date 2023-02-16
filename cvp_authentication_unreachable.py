from bugchecks.bug import Bug
import lib.return_codes as code

class cvp_authentication_unreachable(Bug):
  def __init__(self):
    super(cvp_authentication_unreachable, self).__init__()

  def scan(self):
    value = code.OK
    message = None
    diagnostic_files = []

    error_message = '"errorMessage":"Server unreachable"'
    if self.is_using_local_logs():
      logfile = self.local_directory(directory_type='logs')+'/aaa/aaa.stderr.log'
      logs = self.read_file(logfile, grep=error_message)
    else:
      logfile = 'kubectl logs -l app=aaa|grep \'%s\'' %error_message
      logs = self.run_command(logfile).stdout

    if logs:
      value = code.ERROR
      message = 'One or more configured authentication servers are unreachable.'
      diagnostic_entry = "grep '%s' %s" %(error_message, logfile)
      diagnostic_files.append(diagnostic_entry)

    self.set_status(value, message, diagnostic_files=diagnostic_files)
    return(value)