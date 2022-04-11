from sys import stderr
from bugchecks.bug import Bug
import lib.return_codes as code
import os

class hbase_stuck_operations(Bug):
  def __init__(self):
    super(hbase_stuck_operations, self).__init__()

  def scan(self):
    value = code.OK
    message = None
    logfile = None
    role = self.get_node_role()

    if self.is_using_local_logs():
      directory = self.local_directory(directory_type='logs')+'/hbasemaster'
      for root, dirs, files in os.walk(directory):
        for file in files:
          if file.endswith('.log'):
            logfile = directory + '/' + file
    else:
      directory = '/cvpi/hbase/logs'
      files = self.run_command('ls %s/*.log' %directory).stdout
      for file in files:
        if 'master' in file:
          logfile = file

    if not logfile and role != 'tertiary':
      value = code.UNAVAILABLE
      message = "Could not find hbasemaster's logs in %s" %directory
    elif not logfile and role == 'tertiary':
      pass
    else:
      logfile = self.read_file(logfile)
      for line in logfile:
        if 'STUCK' in line:
          value = code.ERROR
          message = "Stuck operations found in HBase master log files."

    self.set_status(value, message)
    return(value)
