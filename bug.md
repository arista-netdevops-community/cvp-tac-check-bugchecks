# Bug() deprecation warnings
## 3.0.0
- Bugchecks must accept the `force` parameter.

## 4.0.0
- `local_command_output_directory()` will be removed.
- `local_logs_directory()` will be removed.

# Bug() changelog
## 2.11.0
- Add support for declaring files where the issue was detected on set_status()

## 2.10.0
- certificates() supports getting certificates from kubernetes
- certificates.is_valid now support different verifications: expiration date, start date, certificate chain and comparison between k8s and filesystem certificates.
- Fixed a bug where checking the bug engine version might fail

## 2.9.4
- Fix running commands when reading debug logs

## 2.9.3
- Allow explicitly setting the key name when saving cluster values

## 2.9.2
- Prevent timeouts during cvpi command execution

## 2.9.1
- Improve container information debugging messages

## 2.9.0
- Added support for `component_requirements` to pre-scan and pre-patch actions.
- Added timeouts for commands running over ssh.

## 2.8.1
- Fixed cache locking
- Fixed using read_files() on remote hosts

## 2.8.0
- Added the post_scan() method. This is invoked after scanning is completed in all nodes. The goal of this method is to allow bugchecks to perform simple operations, such as cluster-wide value comparisons, and **must not** be used for complex/expensive calls as this doesn't benefit from performance enhancements such as threading.
- Added the save_cluster_value() method. This saves values in a way that can be retrieved by the post_scan() method running in any nodes and can be used to compare values across different nodes.
- Added the get_cluster_values() method. This retrieves values saved by save_cluster_value() from all nodes. Usage example:
```python
def scan(self):
      hostname = self.get_node_name()
      self.save_cluster_value(hostname)
def post_scan(self):
      message = "Primary: %s | Secondary: %s | Tertiary: %s" %(
        self.get_cluster_values().primary,
        self.get_cluster_values().secondary,
        self.get_cluster_values().tertiary
      )
      self.set_status(code.WARNING, message)
```

## 2.7.1
- Do not return the connection object along with bugcheck information

## 2.7.0
- Added the `certificates` child class to make it easier to work with certificates. Sample usage:
```python
expired, expiring = [], []
certificates = self.certificates()
for cert in certificates.list():
  if not certificates.is_valid(cert):
    expired.append(cert)
  elif certificates.is_close_to_expiration(cert):
    expiring.append(cert)
```
## 2.6.0
- Added `all_nodes` parameter to `run_command()`. To evaluate the output you can use the following code:
```python
single_host_result = self.run_command('ls')
if single_host_result == code.OK:
  print("Command succeeded")
  print(single_host_result.stdout)
else:
  print(single_host_result.stderr)

multi_host_result = self.run_command('ls', all_nodes=True)
if multi_host_result == code.OK:
  print("Command succeeded on all hosts")
  for host in multi_host_result.hosts:
    print(eval("multi_host_result."+host+".stdout"))
else:
  print("Command failed on at least one host")
  for host in multi_host_result.hosts:
    if eval("multi_host_result."+host+".exit_code") != code.OK:
      print("Command failed on host " + host)
      print(eval("multi_host_result."+host+".stderr"))
```

## 2.5.4
- Added `force` parameter to the patch stub function. Starting on 3.0.0 all bugchecks
  should accept it as a parameter.

## 2.5.3
- Fix an issue where no results would be returned when using grep on uncached files

## 2.5.2
- Use raw strings for escape sequences

## 2.5.1
- Changed deprecation warnings to use python's built-in warning mechanism

## 2.5.0
- Added `cacheable` parameter to `run_command()`
- Support file caching in read_file()

## 2.4.0
- Added local_directory() which supports returning logs, commands and root directories.
- Deprecated local_command_output_directory(). It will be removed on 4.0.0.
- Deprecated local_logs_directory(). It will be removed on 4.0.0.

## 2.3.1
- Support checking required user privileges during pre_patch() and pre_scan()

## 2.3.0
- Added `grep` parameter to `read_file()`

## 2.2.0
- Added `from_last` parameter to `read_file()`

## 2.1.0
- Added `cvpi()` method
- Added `silence_cvpi_warning` parameter to `run_command()`

## 2.0.0
- `run_command()` method output changed to an object with `stdout`, `stderr` and `exit_code` values.