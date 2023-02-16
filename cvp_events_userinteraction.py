import re
import lib.return_codes as code
from bugchecks.bug import Bug


class cvp_events_userinteraction(Bug):
    def __init__(self):
        super(cvp_events_userinteraction, self).__init__()

    def scan(self):
        value = code.OK
        message = None
        not_found_events = []
        diagnostic_files = []

        grep = "not found for interaction, discarding interaction"
        event_search_regex = r'Target event \((.*)\) not found'

        if self.is_using_local_logs():
            logfile = self.local_directory(directory_type='root')+'/turbine-version-events-active.log'
            logs = self.read_file(logfile, grep=grep)
        else:
            logfile = "kubectl logs -l 'app=turbine-version-events-active'|grep '%s'" % grep
            logs = self.run_command(logfile).stdout

        line_number=1
        for line in logs:
            event = re.search(event_search_regex, line).groups()[0]
            if event and event not in not_found_events:
                not_found_events.append(event)
                diagnostic_entry = "grep '%s.*%s' %s" %(event, grep, logfile)
                diagnostic_files.append(diagnostic_entry)
            line_number += 1

        if not_found_events:
            value = code.ERROR
            message = 'Events not found in user interaction'

        self.set_status(value, message, extra=not_found_events, diagnostic_files=diagnostic_files)
        return value

    def patch(self):
        value = code.ERROR
        message = None
        service = 'turbine-version-events-active'

        output = self.cvpi(action='restart', services=[service])
        if ['restart', service] in output.successful:
            value = code.OK
            message = "restarted %s. Please try to acknowledge the events again." %service
        else:
            message = "failed to restart %s" %service

        return(value, message)
