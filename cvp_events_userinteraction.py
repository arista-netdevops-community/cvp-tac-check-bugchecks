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

        grep = "not found for interaction, discarding interaction"
        event_search_regex = r'Target event \((.*)\) not found'

        if self.is_using_local_logs():
            logs = self.read_file(self.local_directory(
                directory_type='root')+'/turbine-version-events-active.log', grep=grep)
        else:
            logs = self.run_command(
                "kubectl logs -l 'app=turbine-version-events-active'|grep '%s'" % grep).stdout

        for line in logs:
            event = re.search(event_search_regex, line).groups()[0]
            if event and event not in not_found_events:
                not_found_events.append(event)

        if not_found_events:
            value = code.ERROR
            message = 'Events not found in user interaction'

        self.set_status(value, message, extra=not_found_events)
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
