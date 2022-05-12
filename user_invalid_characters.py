# pylint: disable=invalid-name, useless-super-delegation, line-too-long
from bugchecks.bug import Bug
import lib.return_codes as code

import re

class user_invalid_characters(Bug):
    """ Bugcheck description
    """
    def __init__(self):
        super(user_invalid_characters, self).__init__()
        self.invalid_users = []

    def scan(self):
        """ Scan for issues
        """
        value = code.OK
        message = None
        search_string = 'Error in validating user: Allowed special characters in username'
        user_extraction_regex = r'^.*create user ([a-zA-Z0-9#$&%*+,\\\-.;<>=@\^_|~]+)'
        self.invalid_users = []

        if self.is_using_local_logs():
            log_contents = self.read_file(self.local_directory(directory_type='logs') + '/user/user-upgrade.log', grep=search_string)
        else:
            log_contents = self.read_file('/cvpi/apps/cvp/logs/upgrade/user-upgrade.log', grep=search_string)

        for line in log_contents:
            user=re.search(user_extraction_regex, line).groups()[0]
            self.invalid_users.append(user)

        if self.invalid_users:
            value = code.ERROR
            message = "Invalid users found: %s" %','.join(self.invalid_users)

        self.set_status(value, message, self.invalid_users)
        return value

    def patch(self, force=False):
        value = code.OK
        message = None
        apish_method='publish'
        apish_dataset='cvp'
        apish_path=["user","users","ids"]

        if self.invalid_users:
            self.debug("Restarting apiserver...", code.LOG_INFO)
            result = self.cvpi(action='stop', services=['apiserver'])
            if result.failed:
                return code.ERROR, "Failed to stop apiserver"

            result = self.cvpi(action='start', services=['apiserver'])
            if result.failed:
                return code.ERROR, "Failed to start apiserver"

            for user in self.invalid_users:
                self.debug("Removing %s" %user, code.LOG_INFO)
                apish_user_path=apish_path.copy()
                apish_user_path=apish_user_path.append(user)

                self.apish(method=apish_method, dataset=apish_dataset, path=str(apish_user_path), action='delete', key=user)
                self.apish(method=apish_method, dataset=apish_dataset, path=str(apish_path), action='delete', key=user)

            self.debug("Starting CVP...", code.LOG_INFO)
            result = self.cvpi(action='start')
            if result.failed:
                return code.ERROR, "Failed to start CVP"

        return value, message
