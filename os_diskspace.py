import lib.return_codes as code
from bugchecks.bug import Bug

class os_diskspace(Bug):
  def __init__(self):
    super(os_diskspace, self).__init__()

    self.check_partitions = ['/', '/data']
    self.warn_threshold = 70
    self.error_threshold = 90

  def scan(self):
    value = code.OK
    message = ""

    partitions={}
    if self.is_using_local_logs():
      output = self.read_file(self.local_directory(directory_type='commands')+'/df_h')
    else:
      check_command = "df -h " + ' '.join(self.check_partitions)
      output = self.run_command(check_command).stdout

    for line in output:
      partition = line.split()[5]
      usage_pcent = line.split()[4]
      try:
        usage_pcent = int(usage_pcent.strip().replace('%',''))
      except ValueError:
        pass
      else:
        partitions[partition] = usage_pcent

    for partition in self.check_partitions:
      if partitions.get(partition):
        if partitions[partition] >= self.error_threshold:
          value = code.ERROR
          message = message + " (%s usage: %s%%)" % (partition, partitions[partition])
        elif partitions[partition] >= self.warn_threshold:
          message = message + " (%s usage: %s%%)" % (partition, partitions[partition])
          if value < code.WARNING:
            value = code.WARNING
      else:
        message = message + "(%s not available)"
        if value == code.OK:
          value = code.UNAVAILABLE

    if value > code.OK:
      message = "Low free space in partitions" + message

    self.set_status(value, message, partitions)
    return(value)
