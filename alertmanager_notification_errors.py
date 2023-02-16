# pylint: disable=invalid-name, useless-super-delegation
import re
from bugchecks.bug import Bug
import lib.return_codes as code

# The class MUST have the same name as the filename
class alertmanager_notification_errors(Bug):
    def __init__(self):
        super(alertmanager_notification_errors, self).__init__()

    def scan(self):
        value = code.OK
        message = None
        failed_notifications = []
        regex = r'\berr="?.*?\"([\w ]+)'
        diagnostic_files = []

        if self.is_using_local_logs():
            logfile = self.local_directory(directory_type='root') + '/alertmanager-service_alertmanager.log'
            logs = self.read_file(logfile)
        else:
            logfile = "kubectl logs -l 'app=alertmanager-service' -c alertmanager"
            logs = self.run_command(logfile).stdout

        line_number = 1
        for line in logs:
            if 'Error on notify' in line or 'Notify for alerts failed' in line:
                r = re.search(regex, line)
                if r:
                    if r.groups()[0] not in failed_notifications:
                        failed_notifications.append(r.groups()[0])
                        diagnostic_entry = "%s:%s" %(logfile, line_number)
                        diagnostic_files.append(diagnostic_entry)
            line_number += 1

        if failed_notifications:
            value = code.ERROR
            message = "Failure in configured notification platforms: %s" %', '.join(failed_notifications)

        self.set_status(value, message, failed_notifications, diagnostic_files=diagnostic_files)
        return(value)
