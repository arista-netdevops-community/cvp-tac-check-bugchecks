# pylint: disable=invalid-name, useless-super-delegation
from bugchecks.bug import Bug
import lib.return_codes as code

class cvp_files_mismatch(Bug):
    """ Checks for files that should be the same across all nodes but aren't.
    """
    def __init__(self):
        super(cvp_files_mismatch, self).__init__()
        self.file_list = [
            '/etc/cvpi/env',
            '/etc/cvpi/cvpi.key',
            '/cvpi/tls/certs/aerisadmin.crt',
            '/cvpi/tls/certs/ca.crt',
            '/cvpi/tls/certs/saml.crt'
        ]

    def scan(self):
        """ Scan for issues
        """
        value = code.OK
        message = None
        checksum = {}

        if self.is_using_local_logs():
            value = code.UNSUPPORTED
            message = 'Supported only in live mode'
        else:
            for file in self.file_list:
                try:
                    checksum[file] = self.run_command("md5sum %s|awk '{print $1}'" %file).stdout[0]
                except Exception as error_message:
                    self.debug("Error getting checksum for %s: %s" %(file, error_message), code.LOG_DEBUG)
                    checksum[file] = None
            self.save_cluster_value(checksum)

        self.set_status(value, message)
        return value

    def post_scan(self):
        value = code.OK
        message = None
        diff = {}

        if self.is_using_local_logs():
            value = code.UNSUPPORTED
            message = 'Supported only in live mode'
        else:
            primary = self.get_cluster_values().primary
            secondary = self.get_cluster_values().secondary
            tertiary = self.get_cluster_values().tertiary

            self.debug("Primary files: %s" %primary, code.LOG_DEBUG)
            self.debug("Secondary files: %s" %secondary, code.LOG_DEBUG)
            self.debug("Tertiary files: %s" %tertiary, code.LOG_DEBUG)

            for file in self.file_list:
                values = []
                if primary:
                    values.append(primary[file])
                if secondary:
                    values.append(secondary[file])
                if tertiary:
                    values.append(tertiary[file])
                values = set(values)
                if len(values) > 1:
                    self.debug("Checksum mismatch on %s: %s" %(file, str(values)), code.LOG_DEBUG)
                if len(values) == 2:
                    if primary[file] == secondary[file]:
                        diff[file] = 'tertiary'
                    elif primary[file] == tertiary[file]:
                        diff[file] = 'secondary'
                    else:
                        diff[file] = 'primary'
                elif len(values) == 3:
                    diff[file] = 'all'

            message_files = []
            if diff:
                for file in diff:
                    if diff[file] == 'all' or diff[file] == self.get_node_role():
                        value = code.ERROR
                        message_files.append(file)
                if message_files:
                    message = 'Files with different content across nodes: %s' %','.join(message_files)

        self.set_status(value, message, diff)
