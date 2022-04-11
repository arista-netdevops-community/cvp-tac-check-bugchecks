

# alertmanager_notification_errors.py - Failed notifications in alertmanager *(v1.0.0)*

## Description
Errors in sending notifications to configured platforms.

## Action Details
### <u>Scan</u>
Details: Check alertmanager logs for 'Error on notify' or 'Notify for alerts failed' messages

Required privileges: cvp



# ambassador_expired_certs.py - Ambassador cert issues *(v1.1.0)*

## Description
Invalid or mismatching ambassador certificates.

## Conditions
> Bug ID: [666794](https://bb/666794) ([public link](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=666794))<br />

## Action Details
### <u>Scan</u>
Details: Checks for not yet valid, expired or mismatching ambassador certificates and secrets.
#### Steps:
1. Check /etc/cvpi/tls/certs/ambassador.crt (live only)
2. Check ambassador-tls-origin secret (live only)
3. Compare the certificate and secret contents (live only)
4. Check log files for error messages caused by expired ambassador certificates

Required privileges: cvp

### <u>Patch</u>
Recreate ambassador certificate and secret.
#### Steps:
1. Reset ambassador
2. Init ambassador
3. Start all CVP components

Required privileges: cvp



# apish_eventsubscriber.py - Incorrect eventSubscriber entries *(v1.0.1)*

## Description
Certificate upload fails due to stale entries in the database.

## Conditions
> Bug ID: [491453](https://bb/491453) ([public link](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=491453))<br />
> Introduced in: 2020.1.0<br />
> Links: [https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=491453](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=491453)<br />
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/cvp-certs/cvp-certs-gtk](https://sites.google.com/arista.com/cvp-tac/cvp-certs/cvp-certs-gtk)<br />

## Action Details
### <u>Scan</u>
Details: Reads the /eventSubscriber/ids path in the 'cvp' dataset.

Required privileges: cvp

### <u>Patch</u>
Removes all the ids under /eventSubscriber/ids path.

Required privileges: cvp



# apish_ztpmode.py - Incorrect ZtpMode setting for provisioned devices *(v1.0.1)*

## Description
Certain scenarios can lead to ZtpMode being set to "true" for provisioned devices at various paths in the NetDb

## Conditions
> Bug ID: [528983](https://bb/528983) ([public link](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=528983))<br />
> Introduced in: 2019.1.0<br />
> Fixed in: 2021.1.0<br />
> Links: [https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=528983](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=528983)<br />
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-onboarding-issues](https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-onboarding-issues)<br />

> Bug ID: [603699](https://bb/603699) ([public link](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=603699))<br />
> Introduced in: 2019.1.0<br />
> Fixed in: 2021.2.1<br />
> Links: [https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=603699](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=603699)<br />
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-onboarding-issues](https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-onboarding-issues)<br />

## Action Details
### <u>Scan</u>
Details: Reads the /provisioning/device/ids and /ztpService/status/device/ids paths in the 'cvp' dataset to find devices with ZtpMode set to true where the ParentContainerKey value is not equal to 'undefined_container'

Required privileges: cvp

### <u>Patch</u>
Rewrites key values for affected devices in scanned paths to set ZtpMode to false

Required privileges: cvp



# cert_expiration.py - Expired Certificates *(v2.0.0)*

## Description
Expired CVP backend certificates

## Conditions
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/uncommon-issues/components-cannot-come-up-due-to-expired-aeris-certificate-bug591049](https://sites.google.com/arista.com/cvp-tac/uncommon-issues/components-cannot-come-up-due-to-expired-aeris-certificate-bug591049)<br />

## Action Details
### <u>Scan</u>
Details: Checks if backend certificates (`/cvpi/tls/certs/server.crt`, `/cvpi/tls/certs/aerisadmin.crt` and `/cvpi/tls/certs/ca.crt`) have expired or will expire within the next 30 days.

If checking logs we look for pods in the `crashloopbackoff` state and compare it to a list of components that are known to fail if certificates have expired: `aaa`, `aeris-ccapi`, `audit`, `ccapi`, `cloudmanager`, `enroll`, `image`, `inventory`, `snapshot`, `ztp`. If the crashed components match this list, then we indicate that with an error message.

However if CVP services haven't been restarted pods might still be running. In this case we check for services throwing out `Context Deadline Exceeded` messages and compare them to the list mentioned previously. If we have a match we indicate that with a warning message.

Required privileges: cvp

### <u>Patch</u>
Renew backend and CA certificates.
#### Steps:
1. Stop CVP
2. Start aeris
3. Remove the backend certificates
4. Reset and initialize the CA
5. Initialize Aeris
6. Restart Aeris
7. Start all remaining CVP services

Required privileges: cvp



# cert_permissions.py - Wrong Certificate Permissions *(v1.0.3)*

## Description
Wrong permissions or ownership on CVP certificate files.

## Action Details
### <u>Scan</u>
Details: Checks if backend certificates are owned by the `cvp` user and if their permissions match the expected ones.

Required privileges: cvp

### <u>Patch</u>
Correct files ownership and permissions.
#### Steps:
1. Change the certificate files ownership to the `cvp` user and group.
2. Set the expected permissions on the files.

Required privileges: root



# clickhouse_readonly_table.py - Readonly tables in clickhouse *(v2.0.0)*

## Description
Clickhouse fails to start and clover cannot initialize schema due to readonly tables.

## Action Details
### <u>Scan</u>
Details: Check clickhouse logs for 'Table is in readonly mode' messages

Required privileges: cvp

### <u>Patch</u>
Detach and re-attach the affected table.

Required privileges: cvp

### <u>Forced Patch</u>
Reset clickhouse. This will wipe telemetry data.
#### Steps:
1. stop cvp
2. remove org data from clickhouse
3. start zookeeper
4. remove clickhouse path from zookeeper
5. start cvp

Required privileges: cvp



# cve_sa70.py - SA-70 *(v1.0.4)*

## Description
JVM configuration exposes this CVP cluster to CVE-2021-44228

## Conditions
> Introduced in: 2019.1.0<br />
> Fixed in: 2021.2.2<br />
> Links: [https://www.arista.com/en/support/advisories-notices/security-advisories/13425-security-advisory-0070](https://www.arista.com/en/support/advisories-notices/security-advisories/13425-security-advisory-0070), [https://nvd.nist.gov/vuln/detail/CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228), [https://logging.apache.org/log4j/2.x/security.html](https://logging.apache.org/log4j/2.x/security.html)<br />

## Action Details
### <u>Scan</u>
Details: Checks the CVP version and based on that, examines either /cvpi/conf/templates/elasticsearch.jvm.options (2019-2020.2.4) or /cvpi/elasticsearch/conf/jvm.options (2020.3.0+) to determine if log4j2.formatMsgNoLookups=true is set

Required privileges: cvp

### <u>Patch</u>
Writes log4j2.formatMsgNoLookups=true key to JVM options file and rebuilds affected component deployments in the cluster to mitigate CVE

Required privileges: cvp



# cvp_authentication_unreachable.py - Unreachable Auth Servers *(v1.0.3)*

## Description
Configured authentication servers could not be reached.

## Action Details
### <u>Scan</u>
Details: Checks for `Server unreachable` messages in aaa logs.

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# cvp_deadline_exceeded.py - Deadline Exceeded *(v1.0.4)*

## Description
Deadline Exceeded messages in services.

## Action Details
### <u>Scan</u>
Details: Checks for `Context Deadline Exceeded` messages in services.

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# cvp_events_userinteraction.py - User Interaction Events not found *(v1.0.0)*

## Description
Acknowledging events may not work

## Conditions
> Bug ID: [639278](https://bb/639278) ([public link](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=639278))<br />
> Internal Links: [https://bug/639278](https://bug/639278)<br />

## Action Details
### <u>Scan</u>
Details: Checks the turbine-version-events-active.log for not found interactions

Required privileges: cvp

### <u>Patch</u>
Restart the turbine-version-events-active component.

Required privileges: cvp



# cvp_image_missingdefault.py - Missing images in CVP *(v1.0.3)*

## Description
Images are configured in CVP but aren't being loaded by the image service.

## Conditions
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/architecture-and-components/location-of-swi-and-swix-images](https://sites.google.com/arista.com/cvp-tac/architecture-and-components/location-of-swi-and-swix-images), [https://mail.google.com/chat/u/0/#chat/space/AAAAy7qQUss/ZPNnx_y65FQ](https://mail.google.com/chat/u/0/#chat/space/AAAAy7qQUss/ZPNnx_y65FQ)<br />

## Action Details
### <u>Scan</u>
Details: Checks if required images weren't loaded.
#### Steps:
1. Check if there are images that need to be added.
2. Check if the image service wasn't able to find the images.
3. Check if the image service wasn't able to add those missing images

Required privileges: cvp

### <u>Patch</u>
No patch is available. The TAC engineer handling the issue should the provided internal links for instructions on fixing it.



# cvp_missing_apprpms.py - Missing apprpms directory *(v1.0.1)*

## Description
/data/apprpms directory does not exist.

## Conditions
> Bug ID: [634395](https://bb/634395) ([public link](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=634395))<br />
> Introduced in: 2021.2.0<br />

## Action Details
### <u>Scan</u>
Details: Check if /data/apprpms exist.

Required privileges: cvp

### <u>Patch</u>
Create /data/apprpms.

Required privileges: cvp



# cvp_running_components.py - Running Components *(v1.0.1)*

## Description
Enabled CVP components that are not running.

## Action Details
### <u>Scan</u>
Details: Checks if enabled components are not running.

*At the moment this is only supported when running in live mode*

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# cvpi_resources.py - CVPI Resources *(v1.0.5)*

## Description
Loads CVPI resources.

## Action Details
### <u>Scan</u>
Details: Loads CVPI resources and saves them to self['status']['extra']. This is intended to be extended by other bugchecks that need to check those values.

Required privileges: cvp



# cvpi_status.py - CVPI Status *(v1.0.3)*

## Description
Loads CVPI components statuses.

## Action Details
### <u>Scan</u>
Details: Loads CVPI components statuses and saves them to self['status']['extra']. This is intended to be extended by other bugchecks that need to check those values.

Required privileges: cvp



# docker_cgroup.py - Docker cgroup memory allocation failure *(v2.0.2)*

## Description
Docker containers failing to start with cgroup memory allocation error.

## Conditions
> Bug ID: [550147](https://bb/550147) ([public link](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=550147))<br />
> Links: [https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=550147](https://www.arista.com/en/support/software-bug-portal/bugdetail?bug_id=550147), [https://github.com/docker/for-linux/issues/841](https://github.com/docker/for-linux/issues/841)<br />
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/uncommon-issues/pods-fail-to-start-due-to-cgroup-memory-allocation-error](https://sites.google.com/arista.com/cvp-tac/uncommon-issues/pods-fail-to-start-due-to-cgroup-memory-allocation-error)<br />

## Action Details
### <u>Scan</u>
Details: Checks for related error messages and missing settings.
#### Steps:
1. Checks if `cgroup.memory=nokmem` is present on the `GRUB_CMDLINE_LINUX` parameter in `/etc/default/grub`
2. Checks if `cgroup.memory=nokmem` is present on `/proc/cmdline`
3. Checks if there are `cgroup.*cannot allocate memory` messages on kubernetes pods

Required privileges: cvp

### <u>Patch</u>
Apply kernel settings on grub's configuration
#### Steps:
1. Back up the current `/etc/default/grub` file
2. Add `cgroup.memory=nokmem` if not present
3. Regenerate grub configuration

Required privileges: root



# elasticsearch_oom_heap.py - ElasticSearch out of heap space *(v1.0.3)*

## Description
Out of memory errors in elasticsearch due to insufficient heap space.

## Conditions
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/howto/how-to-elasticsearch](https://sites.google.com/arista.com/cvp-tac/howto/how-to-elasticsearch)<br />

## Action Details
### <u>Scan</u>
Details: Checks if there are OutOfMemoryError: Java heap space in elasticsearch logs.

Required privileges: cvp

### <u>Patch</u>
Increase Elasticsearch's memory limits.
#### Steps:
1. Stop elasticsearch
2. Increase elasticsearch memory limits
3. Start CVP

Required privileges: cvp



# hbase_corrupted_procedures.py - HBase corrupted procedures *(v1.0.3)*

## Description
Corrupted procedures in HBase WAL files.

## Conditions
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-hbase](https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-hbase)<br />

## Action Details
### <u>Scan</u>
Details: Checks if there are corrupted procedures on hbase logs.

Required privileges: cvp

### <u>Patch</u>
Fix database inconsistencies using hbck.
#### Steps:
1. Stop all CVP components except for hadoop
2. Move current WAL files to a backup location
3. Start HBase master and regionserver
4. Run hbck
5. Rotate Hbase logs
6. Start CVP

Required privileges: cvp



# hbase_offline_regions.py - hbase_offline_regions *(v1.0.0)*

## Description
Offline hbase regions

## Conditions
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-hbase](https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-hbase)<br />

## Action Details
### <u>Scan</u>
Details: Scan log files looking for offline regions.
#### Steps:
1. Determine current hbase master log file
2. Look for lines containing the string 'Master startup cannot progress, in holding-pattern until region onlined.'
3. Extract and store the region name from matching lines.

Required privileges: cvp

### <u>Patch</u>
Assign offline regions
#### Steps:
1. Assign open offline regions
2. Restart regionserver if regions are not open

Required privileges: root



# hbase_stuck_operations.py - HBase stuck operations *(v1.0.3)*

## Description
HBase operations in STUCK state.

## Conditions
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-hbase](https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-hbase)<br />

## Action Details
### <u>Scan</u>
Details: Checks if there are stuck operations on hbase logs.

Required privileges: cvp



# hbase_unassigned_regions.py - HBase unassigned regions *(v2.0.4)*

## Description
HBase regions not deployed on any region server.

## Conditions
> Internal Links: [https://sites.google.com/arista.com/cvp-tac/uncommon-issues/region-not-deployed-on-any-region-server](https://sites.google.com/arista.com/cvp-tac/uncommon-issues/region-not-deployed-on-any-region-server), [https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-hbase](https://sites.google.com/arista.com/cvp-tac/troubleshooting/troubleshooting-hbase)<br />

## Action Details
### <u>Scan</u>
Details: Checks if there are unassigned regions on hbase.

Required privileges: cvp

### <u>Patch</u>
Assigns unassigned regions using hbase shell.

Required privileges: cvp



# k8s_pods_crashloop.py - Crashed Pods *(v1.0.1)*

## Description
Kubernetes pods in CrashLoopBackOff state.

## Action Details
### <u>Scan</u>
Details: Checks if there are pods in `CrashLoopBackOff` state in kubernetes.

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# k8s_pods_failed.py - Failed K8s pods *(v1.0.1)*

## Description
Kubernetes pods in Failed state.

## Action Details
### <u>Scan</u>
Details: Checks if there are pods in `Failed` state in kubernetes.

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# k8s_pods_pending.py - Pending K8s pods *(v1.0.1)*

## Description
Kubernetes pods in Pending state.

## Action Details
### <u>Scan</u>
Details: Checks if there are pods in `Pending` state in kubernetes.

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# k8s_secrets_missing.py - Missing kubernetes secrets *(v2.0.0)*

## Description
Missing CVP required kubernetes secrets.

## Action Details
### <u>Scan</u>
Details: Checks if required secrets (currently only ambassador-tls-origin) are present on kubernetes.
*This is only supported when running on live mode*

Required privileges: cvp

### <u>Patch</u>
Recreate ambassador certificate and secret.
#### Steps:
1. Reset ambassador
2. Init ambassador
3. Start all CVP components

Required privileges: cvp



# kafka_lag.py - Kafka Lag *(v1.0.3)*

## Description
High Kafka lag on the postDB topic.

## Action Details
### <u>Scan</u>
Details: Checks if the lag in Kafka's postDB topic is above a threshold (500).

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# os_availablememory.py - Available Memory *(v1.0.3)*

## Description
Low ammount of RAM available.

## Action Details
### <u>Scan</u>
Details: Checks if available RAM is below a threshold (2.5gb)

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# os_diskspace.py - Disk Space *(v1.0.3)*

## Description
Disk space is lower than threshold.

## Action Details
### <u>Scan</u>
Details: Checks if disk space usage is above a threshold (70%)

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# os_diskthroughput.py - Disk Throughput *(v1.0.2)*

## Description
Disk throughput below threshold.

## Action Details
### <u>Scan</u>
Details: Checks if the disk bandwidth is below a threshold (50mb/s).

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# os_loadaverage.py - Load Average *(v1.0.3)*

## Description
Load average is higher than the number of CPUs in the node

## Action Details
### <u>Scan</u>
Details: Checks if load average is high by reading `/proc/loadavg` (live) or `cvpi_commands/top` (logs).

It reads all 3 load average measurements (1, 5 and 15 minutes) and takes the highest in consideration, so a warning may still be displayed if there was a recent peak but things are back to normal at the moment the check is done.

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# os_ntpsync.py - NTP Synchronization *(v1.0.1)*

## Description
Server time is not synchronized.

## Action Details
### <u>Scan</u>
Details: Checks the NTP status on the cvpi resources output.

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.



# os_oom.py - OOM errors *(v1.0.4)*

## Description
Services killed due to system running out of memory.

## Action Details
### <u>Scan</u>
Details: Checks if processes have been OOM killed on journalctl and kubelet_journalctl files.

Required privileges: cvp

### <u>Patch</u>
No patch is available. This is an informational message and further debugging will be needed by the TAC team.

