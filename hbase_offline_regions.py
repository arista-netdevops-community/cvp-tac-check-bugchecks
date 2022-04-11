# pylint: disable=invalid-name, useless-super-delegation
from bugchecks.bug import Bug
import lib.return_codes as code

import os
import re

class hbase_offline_regions(Bug):
    """ Bugcheck description
    """
    def __init__(self):
        super(hbase_offline_regions, self).__init__()
        self.offline_regions = []

    def scan(self):
        """ Scan for issues
        """
        value = code.OK
        message = None

        offline_region_regex = r'{(\w+)\b state=(\w+)\b'
        value = code.OK
        self.offline_regions = []
        logfile = None

        if self.is_using_local_logs():
            for root, dirs, files in os.walk(self.local_directory(directory_type='logs')+'/hbasemaster/'):
                for file in files:
                    if file.endswith('.log'):
                        logfile = file
        else:
            directory = '/cvpi/hbase/logs'
            files = self.run_command('ls %s/*.log' %directory).stdout
            for file in files:
                if 'master' in file:
                    logfile = file

        if logfile:
            file = self.read_file(self.local_directory(directory_type='logs')+'/hbasemaster/'+logfile)
            if file:
                for line in file:
                    if 'becomeActiveMaster' in line and 'Master startup cannot progress, in holding-pattern until region onlined.' in line:
                        state = re.search(offline_region_regex, line)
                        if state:
                            if state.groups() not in self.offline_regions:
                                self.offline_regions.append(state.groups())
                        else:
                            self.debug("Couldn't determine region in line: %s" % line, code.LOG_WARNING)

        if self.offline_regions:
            value = code.ERROR
            message = "Offline regions: %s" %', '.join(region for region, state in self.offline_regions)

        self.set_status(value, message, self.offline_regions)
        return value

    def patch(self, force=False):
        value = code.OK
        message = None

        restart_regionserver = False

        if self.cvp_is('<', '2020.1.0'):
            assign_command = 'LOG4J_FORMAT_MSG_NO_LOOKUPS=true HBASE_CLASSPATH_PREFIX=/cvpi/hbase/lib/hbase-hbck2-1.0.0-SNAPSHOT.jar hbase org.apache.hbase.HBCK2 assigns'
        elif self.cvp_is('>=', '2020.1.0') and self.cvp_is('<', '2021.2.0'):
            assign_command = 'LOG4J_FORMAT_MSG_NO_LOOKUPS=true HBASE_CLASSPATH_PREFIX=/cvpi/hbase/hbase-operator-tools/hbase-hbck2/hbase-hbck2-1.0.0.jar hbase org.apache.hbase.HBCK2 assigns'
        elif self.cvp_is('>=', '2021.2.0') and self.cvp_is('<', '2021.2.2'):
            assign_command = 'LOG4J_FORMAT_MSG_NO_LOOKUPS=true HBASE_CLASSPATH_PREFIX=/cvpi/hbase/hbase-operator-tools/hbase-hbck2/hbase-hbck2-1.1.0.jar hbase org.apache.hbase.HBCK2 assigns'
        else:
            assign_command = 'HBASE_CLASSPATH_PREFIX=/cvpi/hbase/hbase-operator-tools/hbase-hbck2/hbase-hbck2-1.2.0.jar hbase org.apache.hbase.HBCK2 assigns'

        self.debug("Trying to assign %s regions..." %len(self.offline_regions), code.LOG_INFO)
        for region, state in self.offline_regions:
            if state.lower() == 'open':
                result = self.run_command(assign_command + " %s" %region)
                if result.exit_code != code.OK:
                    self.debug("Failed to assign region %s" %region, code.LOG_WARNING)
                    self.debug("\nstdout:\n%s" %result.stdout, code.LOG_WARNING)
                    self.debug("\nstderr:\n%s" %result.stderr, code.LOG_WARNING)
            else:
                self.debug("Region %s stuck in %s state. We'll restart regionserver after assignments." %(region, state), code.LOG_WARNING)
                restart_regionserver = True

        if restart_regionserver:
            self.debug("Restarting regionserver...", code.LOG_INFO)
            result = self.cvpi(action='stop', services=['hbase'])
            result = self.cvpi(action='start', services=['regionserver'])
            if not result.failed:
                self.debug("Regionserver restart successful. Starting hbase...", code.LOG_INFO)
                result = self.cvpi(action='start', services=['hbase'])
                if not result.failed:
                    self.debug("Hbase restart successful. Starting all components...", code.LOG_INFO)
                    result = self.cvpi(action='start')
                    if not result.failed:
                        self.debug("CVP is up", code.LOG_INFO)
                else:
                    value = code.ERROR
                    message = "Failed to start hbase"
            else:
                value = code.ERROR
                message = "Failed to start regionserver"

        return value, message