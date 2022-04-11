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

        if self.is_using_local_logs():
            logfile = self.local_directory(directory_type='root') + '/alertmanager-service_alertmanager.log'
            logs = self.read_file(logfile)
        else:
            logs = self.run_command("kubectl logs -l 'app=alertmanager-service' -c alertmanager").stdout

        for line in logs:
            if 'Error on notify' in line or 'Notify for alerts failed' in line:
                r = re.search(regex, line)
                if r:
                    if r.groups()[0] not in failed_notifications:
                        failed_notifications.append(r.groups()[0])

        if failed_notifications:
            value = code.ERROR
            message = "Failure in configured notification platforms: %s" %', '.join(failed_notifications)

        self.set_status(value, message, failed_notifications)
        return(value)
