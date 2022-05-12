# standard imports
import json

# project imports
import lib.return_codes as return_codes
from bugchecks.bug import Bug


class apish_ztpmode(Bug):
    def __init__(self):
        super(apish_ztpmode, self).__init__()
        self._devices = []
        self._affected_devices = []
        self._value = return_codes.OK

    def _scan_logs(self):
        value = return_codes.UNSUPPORTED
        message = "This issue cannot be checked from debug logs"
        return (value, message)

    def _get_provisioned_devices(self):
        device_output = json.loads(self.apish('get', 'cvp', '/provisioning/device/ids', action=None, key=None)[0])
        for item in device_output['Notifications']:
            # the structure of this output is such that we expect 1 key under 'updates' for each item in the
            # Notifications array where the key value is the device ID
            for key in item['updates'].keys():
                self._devices.append(key)

    def _check_provisioned_devices(self):
        for device in self._devices:
            self.debug("Getting provisioning path data for {}".format(device), return_codes.LOG_DEBUG)
            provisioning_output = json.loads(
                self.apish('get', 'cvp', '/provisioning/device/ids/{}'.format(device), action=None,
                           key=None)[0])
            provisioning_output = provisioning_output['Notifications'][0]['updates'][device]['value']

            # ztpService status path isn't always set, make sure to handle a null output
            # empty list is false in python
            self.debug("Getting ztpService path data for {}".format(device), return_codes.LOG_DEBUG)
            ztpstatus_output = self.apish('get', 'cvp', '/ztpService/status/device/ids/{}'.format(device), action=None,
                                          key=None)
            if ztpstatus_output:
                ztpstatus_output = json.loads(ztpstatus_output[0])
                ztpstatus_output = ztpstatus_output['Notifications'][0]['updates'][device]['value']
            else:
                ztpstatus_output = None

            if provisioning_output['ParentContainerKey'] != "undefined_container":
                # ztpmode is true and device is not in the undefined container, this is always wrong
                if provisioning_output['ZtpMode']:
                    self.debug("Device ZTP mode in provisioning is true, and should not be", return_codes.LOG_DEBUG)

                    # append a tuple of device ID, affected path
                    self._value = return_codes.ERROR
                    self._affected_devices.append((device, '/provisioning/device/ids', False))

                if ztpstatus_output is not None:
                    if ztpstatus_output['ZtpMode']:
                        self.debug("Device ZTP mode in ztpService path is true, and should not be",
                                   return_codes.LOG_DEBUG)

                        # append a tuple of device ID, affected path
                        self._value = return_codes.ERROR
                        self._affected_devices.append((device, '/ztpService/status/device/ids', False))
            else:
                # devices in the undefined container need a different set of logic applied - we compare against the
                # device dataset, verify the device-reported ZTP state matches the provisioning dataset ZTP state
                self.debug("Getting sysDB zerotouch status from device dataset for {}".format(device),
                           return_codes.LOG_DEBUG)
                sysdb_ztpstatus_output = self.apish('get', device, '/Sysdb/zerotouch/status', action=None, key=None)
                if sysdb_ztpstatus_output:
                    sysdb_ztpstatus_output = json.loads(sysdb_ztpstatus_output[0])
                    for notif in sysdb_ztpstatus_output['Notifications']:
                        if 'enabled' in notif['updates'].keys():
                            sysdb_ztpstatus_output = notif['updates']
                else:
                    sysdb_ztpstatus_output = None

                if sysdb_ztpstatus_output is not None:
                    if provisioning_output['ZtpMode'] != sysdb_ztpstatus_output['enabled']['value']:
                        self.debug(
                            "Device ZTP mode reported in Sysdb path does not match CVP ZTP mode for device in provisioning path",
                            return_codes.LOG_DEBUG)

                        self._value = return_codes.ERROR
                        self._affected_devices.append(
                            (device, '/provisioning/device/ids', sysdb_ztpstatus_output['enabled']['value']))

                    if ztpstatus_output is not None:
                        if ztpstatus_output['ZtpMode'] != sysdb_ztpstatus_output['enabled']['value']:
                            self.debug(
                                "Device ZTP mode reported in Sysdb path does not match CVP ZTP mode for ztpService path",
                                return_codes.LOG_DEBUG)

                            self._value = return_codes.ERROR
                            self._affected_devices.append(
                                (device, '/ztpService/status/device/ids', sysdb_ztpstatus_output['enabled']['value']))
                else:
                    self.debug(
                        "Could not extract sysDB zerotouch data from apish response for device {}".format(device),
                        return_codes.LOG_DEBUG)

    def scan(self):
        # reset values at beginning of new scan
        self._value = return_codes.OK
        self._affected_devices = []
        message = 'No ZTP mode issues found'

        if self.is_using_local_logs():
            self.debug("This issue cannot be checked from debug logs", return_codes.LOG_DEBUG)
            self._value, message = self._scan_logs()
        else:
            self.debug("Checking NetDB via apish", return_codes.LOG_DEBUG)
            self._get_provisioned_devices()
            self._check_provisioned_devices()

            if self._value == return_codes.ERROR:
                path_messages = []
                for device, path, mode_set in self._affected_devices:
                    path_messages.append('ZTP mode issue found for {} in path {}. ZTP value will be corrected to {}'.format(device, path, mode_set))
                message = '\n'.join(path_messages)

        self.set_status(self._value, message, [x[0] for x in self._affected_devices])
        return self._value

    def patch(self):
        value = return_codes.OK
        message = None

        for device, path, mode_set in self._affected_devices:
            # pull current key value, set ZtpMode to false, shove new key value into hbase
            path_value = json.loads(self.apish('get', 'cvp', '{}/{}'.format(path, device), action=None, key=None)[0])
            path_value['Notifications'][0]['updates'][device]['value']['ZtpMode'] = mode_set
            payload = "'" + json.dumps(path_value['Notifications'][0]['updates'][device]) + "'"

            self.apish('publish', 'cvp', '{}/{}'.format(path, device), action='update', key=payload)

        return value, message
