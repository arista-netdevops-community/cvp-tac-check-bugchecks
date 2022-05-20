from bugchecks.bug import Bug
import lib.return_codes as code
import os
import re

class hbase_corrupted_procedures(Bug):
  def __init__(self):
    super(hbase_corrupted_procedures, self).__init__()

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
      logfile = self.read_file(logfile, grep='corrupted procedures')
      for line in logfile:
        if 'corrupted procedures' in line:
          value = code.ERROR
          message = "Corrupted files found in HBase master log files."

    self.set_status(value, message)
    return(value)

  def patch(self):
    value = code.OK
    message = None
    hdfs_backup_dir='/tmp/walbackup'

    self.debug("Stopping CVP", code.LOG_INFO)
    self.cvpi(action='stop')
    
    self.debug("Starting hadoop", code.LOG_INFO)
    self.cvpi(action='start', services=['hadoop'])
    
    self.debug("Backing up WAL files to %s" %hdfs_backup_dir, code.LOG_INFO)
    self.run_command("su - cvp -c 'hdfs dfs -mkdir -p /tmp/walbackup'")
    self.run_command("su - cvp -c 'hdfs dfs -mv /hbase/MasterProcWALs/* /tmp/walbackup'")

    self.debug("Starting hbase", code.LOG_INFO)
    self.cvpi(action='start', services=['hbasemaster', 'regionserver'])

    self.debug("Running hbck", code.LOG_INFO)
    self.run_command("su - cvp -c 'hbase hbck'")

    self.debug("Stopping CVP", code.LOG_INFO)
    self.cvpi(action='stop')

    self.debug("Rotating logs", code.LOG_INFO)
    self.run_command("logrotate -f /etc/logrotate.d/cvp 2>/dev/null")

    self.debug("Starting CVP", code.LOG_INFO)
    self.cvpi(action='start')

    return(value, message)
