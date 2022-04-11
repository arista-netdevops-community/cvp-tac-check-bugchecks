from bugchecks.bug import Bug
import lib.return_codes as code

class cvp_missing_apprpms(Bug):
  def __init__(self):
    super(cvp_missing_apprpms, self).__init__()

  def scan(self):
    value = code.OK
    message = None

    if not self.is_using_local_logs:
      directory = self.run_command("ls -d /data/apprpms").stdout
      if not directory:
        value = code.WARNING
        message = "Missing /data/apprpms directory. Installing CVP extensions may fail."

    self.set_status(value, message)
    return(value)

  def patch(self):
    value = code.OK
    message = None

    result = self.run_command("su - cvp -c 'mkdir -p /data/apprpms'")
    value = result.exit_code
    message = result.stderr

    return(value, message)
