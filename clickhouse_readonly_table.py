# pylint: disable=invalid-name, useless-super-delegation, arguments-differ, line-too-long, consider-using-dict-items
import re

from bugchecks.bug import Bug
import lib.return_codes as code

class clickhouse_readonly_table(Bug):
    """ Bugcheck description
    """
    def __init__(self):
        super(clickhouse_readonly_table, self).__init__()
        self.error_messages = [
            'Table is in readonly mode',
            'No node'
        ]

    def scan(self):
        """ Scan for issues
        """
        # Steps to detect a problem go here
        value = code.OK
        message = None

        zk_path_regex = r'path: ([\w\/.]*)'
        zk_table_regex = r'in query:.*INTO \"(\w+)\"\.\"(\w+)'
        issues = {}

        if self.is_using_local_logs():
            logfile = self.local_directory(directory_type='logs')+'/clickhouse/clickhouse-server.err.log'
        else:
            logfile = '/cvpi/clickhouse/logs/clickhouse-server/clickhouse-server.err.log'
        logs = self.read_file(logfile, grep='::Exception')

        for line in logs:
            for error_message in self.error_messages:
                if error_message in line:
                    if not issues.get(error_message):
                        issues[error_message] = {}
                        issues[error_message]['paths'] = []
                        issues[error_message]['tables'] = []

                    value = code.WARNING
                    path = re.search(zk_path_regex, line)
                    table = re.search(zk_table_regex, line)
                    if path or table:
                        if path:
                            value = code.ERROR
                            path = path.groups()[0]
                            if path not in issues[error_message]['paths']:
                                issues[error_message]['paths'].append(path)
                        if table:
                            value = code.WARNING
                            namespace = table.groups()[0] + '.' + table.groups()[1]
                            if namespace not in issues[error_message]['tables']:
                                issues[error_message]['tables'].append(namespace)
                    else:
                        self.debug("Could not extract paths or tables from line: %s" %line, code.LOG_WARNING)

        for issue in issues:
            if issues[issue]['paths'] or issues[issue]['tables']:
                message = ''
                if issues[issue]["paths"]:
                    self.debug("%s %s paths found in %s log lines" %(len(issues[issue]['paths']), issue,len(logs)), code.LOG_DEBUG)
                    message = message + '%s paths: %s' %(issue, ', '.join(issues[issue]['paths'])) + '\n'
                if issues[issue]["tables"]:
                    self.debug("%s %s tables found in %s log lines" %(len(issues[issue]['tables']), issue, len(logs)), code.LOG_DEBUG)
                    message = message + '%s tables: %s' %(issue, ', '.join(issues[issue]['tables'])) + '\n'
            else:
                self.debug("No issues found in %s log lines" %len(logs), code.LOG_DEBUG)

        self.set_status(value, message, issues)
        return value

    def patch(self, force=False):
        value = code.OK
        message = None
        issues = self.get_status(section='extra')
        ro_table_regex = r'tables\/(.*)\/(.*)$'

        if force:
            self.debug("Stopping CVP. This may take a while...", code.LOG_INFO)
            self.cvpi(action='stop')

            self.debug("Removing clickhouse org data...", code.LOG_INFO)
            command = "rm -Rf /data/clickhouse/*data/org*"
            multi_host_result = self.run_command(command, all_nodes=True)
            if multi_host_result.exit_code != code.OK:
                self.debug("Command %s failed on at least one host" %command, code.LOG_WARNING)
                for host in multi_host_result.hosts:
                    if eval("multi_host_result."+host+".exit_code") != code.OK:
                        self.debug("%s: %s" %(host, eval("multi_host_result."+host+".stderr")), code.LOG_WARNING)

            self.debug("Starting zookeeper...")
            self.cvpi(action='start', services=['zookeeper'])

            self.debug("Removing clickhouse data from zookeeper...", code.LOG_INFO)
            result = self.run_command("/cvpi/zookeeper/bin/zkCli.sh deleteall /clickhouse")
            if result.exit_code != code.OK:
                self.run_command("/cvpi/zookeeper/bin/zkCli.sh rmr /clickhouse")

            self.debug("Starting CVP. This may take a while...")
            self.cvpi(action='start')
        elif issues.get('Table is in readonly mode'):
            readonly = issues['Table is in readonly mode']
            if readonly.get('paths'):
                if not force:
                    for path in readonly['paths']:
                        _search = re.search(ro_table_regex, path)
                        if _search:
                            org = _search.groups()[0]
                            table = _search.groups()[1]

                            self.debug("Trying to reattach %s.%s" %(org, table), code.LOG_WARNING)
                            if self.cvp_is('>=', '2021.0.0'):
                                command = "kubectl exet -ti clickhouse-0 -- bash -c 'HOME=/tmp; clickhouse client --host 127.0.0.1 --port 17000 --query \"DETACH TABLE %s.%s ON CLUSTER default\"'" %(org, table)
                            else:
                                command = "/cvpi/clickhouse/bin/clickhouse client --host 127.0.0.1 --port 17000 --query \"DETACH TABLE %s.%s ON CLUSTER default\"'" %(org, table)
                            result = self.run_command(command)

                            if result.exit_code != code.OK:
                                self.debug("Error while unattaching %s.%s: %s" %(org, table, result.stderr), code.LOG_WARNING)
                                self.debug("Continuing anyway...", code.LOG_WARNING)

                            if self.cvp_is('>=', '2021.0.0'):
                                command = "kubectl exet -ti clickhouse-0 -- bash -c 'HOME=/tmp; clickhouse client --host 127.0.0.1 --port 17000 --query \"ATTACH TABLE %s.%s ON CLUSTER default\"'" %(org, table)
                            else:
                                command = "/cvpi/clickhouse/bin/clickhouse client --host 127.0.0.1 --port 17000 --query \"ATTACH TABLE %s.%s ON CLUSTER default\"'" %(org, table)
                            result = self.run_command(command)
                            value = result.exit_code
                            message = result.stderr
            else:
                value = code.WARNING
                message = "No readonly paths found. You may need to reset clickhouse."
        else:
            value = code.WARNING
            message = "No readonly paths found. You may need to reset clickhouse."

        return value, message
