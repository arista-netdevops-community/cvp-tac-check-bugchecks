# pylint: disable=invalid-name, useless-super-delegation, line-too-long
from datetime import datetime
from OpenSSL import crypto
from bugchecks.bug import Bug
import lib.return_codes as code

class ambassador_expired_certs(Bug):
    """ Bugcheck description
    """
    def __init__(self):
        super(ambassador_expired_certs, self).__init__()

    def scan_remote(self):
        ''' Live scan '''
        value = code.OK
        message = None
        date_format, encoding, now = "%Y%m%d%H%M%SZ", "ascii", datetime.now()
        ambassador_cert = {}

        ambassador_cert['file'] = {}
        ambassador_cert['file']['name'] = '/cvpi/tls/certs/ambassador.crt'
        try:
            ambassador_cert['file']['contents'] = self.read_file(ambassador_cert['file']['name'])
        except Exception as error:
            value = code.ERROR
            message = "Could not open ambassador cert file %s: %s" %(ambassador_cert['file']['name'], error)
            return value, message

        try:
            ambassador_cert['file']['cert'] = crypto.load_certificate(crypto.FILETYPE_PEM, ambassador_cert['file']['contents'])
            ambassador_cert['file']['not_before'] = datetime.strptime(ambassador_cert['file']['cert'].get_notBefore().decode(encoding), date_format)
            ambassador_cert['file']['not_after'] = datetime.strptime(ambassador_cert['file']['cert'].get_notAfter().decode(encoding), date_format)
        except Exception as error:
            value = code.ERROR
            message = "Could not load ambassador cert file %s: %s" %(ambassador_cert['file']['name'], error)
            return value, message

        ambassador_cert['secret'] = {}
        ambassador_cert['secret']['name'] = 'ambassador-tls-origin'
        try:
            ambassador_cert['secret']['contents'] = self.run_command("kubectl get secret %s -o 'go-template={{ index .data \"tls.crt\"}}'|base64 -d" %ambassador_cert['secret']['name']).stdout
        except Exception as error:
            value = code.ERROR
            message = "Could not read ambassador cert secret %s: %s" %(ambassador_cert['secret']['name'], error)
            return value, message

        try:
            ambassador_cert['secret']['cert'] = crypto.load_certificate(crypto.FILETYPE_PEM, ambassador_cert['secret']['contents'])
            ambassador_cert['secret']['not_before'] = datetime.strptime(ambassador_cert['secret']['cert'].get_notBefore().decode(encoding), date_format)
            ambassador_cert['secret']['not_after'] = datetime.strptime(ambassador_cert['secret']['cert'].get_notAfter().decode(encoding), date_format)
        except Exception as error:
            value = code.ERROR
            message = "Could not load ambassador cert secret %s: %s" %(ambassador_cert['secret']['name'], error)
            return value, message

        for cert in ambassador_cert.items():
            if now < ambassador_cert[cert]['not_before']:
                value = code.ERROR
                message = "Ambassador cert %s not valid yet" %cert
            elif now > ambassador_cert[cert]['not_after']:
                value = code.ERROR
                message = "Ambassador cert %s has expired" %cert
        if ambassador_cert['file']['cert'].get_pubkey() != ambassador_cert['secret']['cert'].get_pubkey():
            if value != code.ERROR:
                value = code.WARNING
            msg = "Mismatch between ambassador cert file and kubernetes secret"
            if message:
                message = message + '. ' + msg
            else:
                message = msg

        return value, message

    def scan(self):
        """ Scan for issues
        """
        value = code.OK
        message = None

        if not self.is_using_local_logs():
            value, message = self.scan_remote()

        if value == code.OK:
            errors = None
            error_message = 'rpc error: code = Unauthenticated desc = not authenticated'
            if self.is_using_local_logs():
                logfile = self.local_directory('commands')+'/journalctl'
                errors = self.read_file(logfile, grep=error_message)
            else:
                errors = self.run_command("journalctl|grep '%s'" %error_message).stdout
            if errors:
                value = code.INFO
                message = 'Service authentication errors found in logs. This might not be an issue.'
        else:
            self.debug("Found certificate issues: %s. Skipping log checks." %message, code.LOG_DEBUG)

        self.set_status(value, message)
        return value

    def patch(self, force=False):
        value = code.OK
        message = None

        self.debug("Resetting ambassador...", code.LOG_INFO)
        failed = self.cvpi(action='reset', services=['ambassador']).failed
        if not failed:
            self.debug("Initializing ambassador...", code.LOG_INFO)
            failed = self.cvpi(action='init', services=['ambassador']).failed
            if failed:
                message = "Ambassador init failed"
                value = code.WARNING
        else:
            message = "Ambassador reset failed"
            value = code.WARNING

        self.debug("Starting CVP...", code.LOG_INFO)
        failed = self.cvpi(action='start').failed
        if failed:
            message = "Failed to start CVP"
            value = code.ERROR

        return value, message