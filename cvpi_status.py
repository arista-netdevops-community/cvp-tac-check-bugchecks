# pylint: disable=invalid-name, useless-super-delegation, arguments-differ, line-too-long, consider-using-dict-items, missing-class-docstring
from bugchecks.bug import Bug
import lib.return_codes as code

import yaml

class cvpi_status(Bug):
    def __init__(self):
        super(cvpi_status, self).__init__()

    def __get_index(self, element_list, element_filter):
        retval = None
        try:
            retval = element_list.index(element_filter)
        except ValueError:
            try:
                retval = element_list.index(element_filter.encode())
            except ValueError:
                pass
        return retval

    def __scan_logs(self):
        return([code.UNSUPPORTED, []])

    def __scan_node(self):
        value = code.OK
        status = {}

        cvpi_check_command = "cvpi status --yaml"
        cvpi_check_output = self.run_command(cvpi_check_command, silence_cvpi_warning=True, cacheable=True).stdout
        index_component = self.__get_index(cvpi_check_output, 'Component Status')
        index_cluster = self.__get_index(cvpi_check_output, 'Cluster Status')
        index_systemd = self.__get_index(cvpi_check_output, 'Systemd Unit Status')

        if self.get_cluster_mode() == 'singlenode':
            component_types = ['component', 'systemd']
        else:
            component_types = ['component', 'cluster', 'systemd']

        for component_type in component_types:
            status[component_type] = {}
            if component_type == 'component':
                if index_cluster:
                    components = cvpi_check_output[index_component+1:index_cluster]
                else:
                    components = cvpi_check_output[index_component+1:index_systemd]
            elif component_type == 'cluster':
                components = cvpi_check_output[index_cluster+1:index_systemd]
            elif component_type == 'systemd':
                components = cvpi_check_output[index_systemd+1:]

            components = yaml.safe_load('\n'.join(components))
            if components:
                for component in components:
                    if component['node'] == self.get_node_role():
                        name = component['component']
                        exitcode = component['result']['exitcode']
                        status[component_type][name] = exitcode

        return([value, status])

    def scan(self):
        value = code.OK
        message = None
        components = None

        if self.is_using_local_logs():
            self.debug("Scanning debug logs", code.LOG_DEBUG)
            value, components = self.__scan_logs()
        else:
            try:
                if self.get_node_role() == 'primary':
                    value, components = self.get_cluster_values(keyname='cvpi_status').primary
                elif self.get_node_role() == 'secondary':
                    value, components = self.get_cluster_values(keyname='cvpi_status').secondary
                elif self.get_node_role() == 'tertiary':
                    value, components = self.get_cluster_values(keyname='cvpi_status').tertiary
            except Exception:
                self.debug("No stored values found for the %s node" %self.get_node_role(), code.LOG_DEBUG)

            if not components:
                self.debug("Performing live scan", code.LOG_DEBUG)
                value, components = self.__scan_node()

        self.set_status(value, message, components)
        self.save_cluster_value([value, components], keyname='cvpi_status')
        return value
