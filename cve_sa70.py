# standard imports
import json
import re

# project imports
import lib.return_codes as return_codes
from bugchecks.bug import Bug


class cve_sa70(Bug):
    def __init__(self):
        super(cve_sa70, self).__init__()
        self._node_status = []
        self._old_format = False
        self._value = return_codes.OK

    def _scan_logs(self):
        value = return_codes.UNSUPPORTED
        message = "This issue cannot be checked from debug logs"
        return (value, message)

    def _search_running(self):
        """
        We have 4 possible states here:
        * Enabled, running       <-- Majority of scenarios
        * Enabled, not running   <-- Could be in this state for a number of reasons
        * Disabled, running      <-- Could be here if customer disabled search as a first-line mitigation for this SA and forgot to kill the process
        * Disabled, not running  <-- Could be in this state for a number of reasons

        The fun part is that in the latter two cases, cvpi status will merely output that the component is disabled,
        not that the processes are still running. In such a scenario, we want to kill off any ES processes still running.

        We also don't want to turn search back on if a customer had it disabled. This is easy in k8s (pod resources
        won't get recreated), but in non-k8s versions, we need to skip the component start command.

        As such, reduce this to a bool we return as to whether the component is disabled or not. If the component is NOT disabled,
        we cycle the component elsewhere in this class regardless of current state. If the component IS disabled,
        elsewhere in the code we will patch the JVM options file, kill any ES processes hanging around, but not start/restart the components.
        Partial disable/enable of the search component is not a scenario we handle.
        """
        search_enabled = True

        stdout = self.run_command(r"cvpi status search -v=3 | grep '(D) DISABLED'").stdout
        if len(stdout) > 0:
            search_enabled = False

        return search_enabled

    def scan(self):
        if self.is_using_local_logs():
            self.debug("This issue cannot be checked from debug logs", return_codes.LOG_DEBUG)
            self._value, message = self._scan_logs()
        else:
            self._old_format = self.cvp_is('older or equal', '2020.2.4')
            if self._old_format:
                stdout = self.run_command(
                    r"cat /cvpi/conf/templates/elasticsearch.jvm.options | grep -E 'log4j2\.formatMsgNoLookups=true'").stdout
            else:
                stdout = self.run_command(
                    r"cat /cvpi/elasticsearch/conf/jvm.options | grep -E 'log4j2\.formatMsgNoLookups=true'").stdout

            # content, grep found the mitigation
            if len(stdout) > 0:
                self.debug('log4j2 mitigation is already set, nothing to do', return_codes.LOG_DEBUG)
                self._value = return_codes.OK
                self.set_status(self._value, "CVE-2021-44228 is patched")
            else:
                self.debug('log4j2 mitigation is not set, will need to be fixed', return_codes.LOG_DEBUG)
                self._value = return_codes.ERROR
                self.set_status(self._value, "CVE-2021-44228 needs to be mitigated on this cluster")

        return self._value

    def patch(self):
        """
        Run all mitigation actions from the primary node instead of on a node-by-node basis
        This avoids any concerns around ordering of actions and ensures by the time we go to roll components,
        all nodes are using a patched config file
        """
        if self.get_cluster_mode() == 'singlenode' or (
                self.get_cluster_mode() == 'multinode' and self.get_node_role() == 'primary'):
            if self._old_format:
                self.debug('Patching JVM options file for old-format cluster', return_codes.LOG_DEBUG)
                _output = self.run_command(
                    r"sed -i 's/-Dlog4j2.disable.jmx=true/-Dlog4j2.disable.jmx=true\n-Dlog4j2.formatMsgNoLookups=true/g' /cvpi/conf/templates/elasticsearch.jvm.options").stdout

                if self.get_cluster_mode() == 'multinode':
                    self.debug('Copying patched JVM options file to secondary and tertiary node',
                               return_codes.LOG_DEBUG)
                    _output = self.run_command(
                        r'su - cvp -c "scp /cvpi/conf/templates/elasticsearch.jvm.options $SECONDARY_HOSTNAME:/cvpi/conf/templates/elasticsearch.jvm.options"').stdout
                    _output = self.run_command(
                        r'su - cvp -c "scp /cvpi/conf/templates/elasticsearch.jvm.options $TERTIARY_HOSTNAME:/cvpi/conf/templates/elasticsearch.jvm.options"').stdout

                _output = self.run_command('cvpi config all').stdout
                if self._search_running():
                    self.debug('Search components are running, bouncing components to pick up patch changes',
                               return_codes.LOG_DEBUG)
                    _output = self.run_command('cvpi stop search').stdout
                    _output = self.run_command('cvpi start search').stdout
                else:
                    self.debug('Search components are not running, verifying no ES processes are still hanging around',
                               return_codes.LOG_DEBUG)
                    # you can't START a disabled component, but you can STOP it
                    _stdout = self.run_command('cvpi stop search').stdout

            else:
                _output = self.run_command(
                    r"sed -i 's/-Dlog4j2.disable.jmx=true/-Dlog4j2.disable.jmx=true\n-Dlog4j2.formatMsgNoLookups=true/g' /cvpi/elasticsearch/conf/jvm.options").stdout

                if self.get_cluster_mode() == 'multinode':
                    self.debug('Copying patched JVM options file to secondary and tertiary node',
                               return_codes.LOG_DEBUG)
                    _output = self.run_command(
                        r'su - cvp -c "scp /cvpi/elasticsearch/conf/jvm.options $SECONDARY_HOSTNAME:/cvpi/elasticsearch/conf/jvm.options"').stdout
                    _output = self.run_command(
                        r'su - cvp -c "scp /cvpi/elasticsearch/conf/jvm.options $TERTIARY_HOSTNAME:/cvpi/elasticsearch/conf/jvm.options"').stdout

                if self._search_running():
                    self.debug('Search components are running, bouncing components to pick up patch changes',
                               return_codes.LOG_DEBUG)
                    _output = self.run_command('kubectl delete pod -l app=elasticsearch-server').stdout
                else:
                    self.debug('Search components are not running, verifying no ES processes are still hanging around',
                               return_codes.LOG_DEBUG)
                    # you can't START a disabled component, but you can STOP it
                    _stdout = self.run_command('cvpi stop search').stdout

        return return_codes.OK, "JVM options have been patched with mitigation"
