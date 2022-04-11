from bugchecks.bug import Bug
import lib.return_codes as code

class cvp_authentication_unreachable(Bug):
  def __init__(self):
    super(cvp_authentication_unreachable, self).__init__()

  def scan(self):
    value = code.OK
    message = None

    error_message = '"errorMessage":"Server unreachable"'
    if self.is_using_local_logs():
      logs = self.read_file(self.local_directory(directory_type='logs')+'/aaa/aaa.stderr.log', grep=error_message)
    else:
      logs = self.run_command('kubectl logs -l app=aaa|grep \'%s\'' %error_message).stdout

    if logs:
      value = code.ERROR
      message = 'One or more configured authentication servers are unreachable.'
    
    self.set_status(value, message)
    return(value)