![](https://img.shields.io/badge/Ansible-ossec-green.svg?logo=angular&style=for-the-badge)

>__Please note that the original design goal of this role was more concerned with the initial installation and bootstrapping environment, which currently does not involve performing continuous maintenance, and therefore are only suitable for testing and development purposes,  should not be used in production environments.__

>__请注意，此角色的最初设计目标更关注初始安装和引导环境，目前不涉及执行连续维护，因此仅适用于测试和开发目的，不应在生产环境中使用。__
___

<p><img src="https://raw.githubusercontent.com/goldstrike77/goldstrike77.github.io/master/img/logo/logo_wazuh.png" align="right" /></p>

__Table of Contents__

- [Overview](#overview)
  * [Architecture](#Architecture)
- [Requirements](#requirements)
  * [Operating systems](#operating-systems)
  * [Wazuh Versions](#wazuh-versions)
- [ Role variables](#Role-variables)
  * [Main Configuration](#Main-parameters)
  * [Other Configuration](#Other-parameters)
- [Dependencies](#dependencies)
- [Example Playbook](#example-playbook)
  * [Hosts inventory file](#Hosts-inventory-file)
  * [Vars in role configuration](#vars-in-role-configuration)
  * [Combination of group vars and playbook](#combination-of-group-vars-and-playbook)
- [License](#license)
- [Author Information](#author-information)
- [Contributors](#Contributors)

## Overview
Wazuh is a free and open source platform for threat detection, security monitoring, incident response and regulatory compliance. It can be used to monitor endpoints, cloud services and containers, and to aggregate and analyze data from external sources. Wazuh OpenSource Security Analytics provides a production-ready setup to analyze your IT environment. It packs with a lot of features which intently need for critical business:

#### Security Analytics
Wazuh is used to collect, aggregate, index and analyze security data, helping organizations detect intrusions, threats and behavioral anomalies.
As cyber threats are becoming more sophisticated, real-time monitoring and security analysis are needed for fast threat detection and remediation. That is why our light-weight agent provides the necessary monitoring and response capabilities, while our server component provides the security intelligence and performs data analysis.

#### Intrusion Detection
Wazuh agents scan the monitored systems looking for malware, rootkits and suspicious anomalies. They can detect hidden files, cloaked processes or unregistered network listeners, as well as inconsistencies in system call responses.
In addition to agent capabilities, the server component uses a signature-based approach to intrusion detection, using its regular expression engine to analyze collected log data and look for indicators of compromise.

#### Log Data Analysis
Wazuh agents read operating system and application logs, and securely forward them to a central manager for rule-based analysis and storage.
The Wazuh rules help make you aware of application or system errors, misconfigurations, attempted and/or successful malicious activities, policy violations and a variety of other security and operational issues.

#### File Integrity Monitoring
Wazuh monitors the file system, identifying changes in content, permissions, ownership, and attributes of files that you need to keep an eye on. In addition, it natively identifies users and applications used to create or modify files.
File integrity monitoring capabilities can be used in combination with threat intelligence to identify threats or compromised hosts. In addition, several regulatory compliance standards, such as PCI DSS, require it.

#### Vulnerability Detection
Wazuh agents pull software inventory data and send this information to the server, where it is correlated with continuously updated CVE (Common Vulnerabilities and Exposure) databases, in order to identify well-known vulnerable software.
Automated vulnerability assessment helps you find the weak spots in your critical assets and take corrective action before attackers exploit them to sabotage your business or steal confidential data.

#### Configuration Assessment
Wazuh monitors system and application configuration settings to ensure they are compliant with your security policies, standards and/or hardening guides. Agents perform periodic scans to detect applications that are known to be vulnerable, unpatched, or insecurely configured.
Additionally, configuration checks can be customized, tailoring them to properly align with your organization. Alerts include recommendations for better configuration, references and mapping with regulatory compliance.

#### Incident Response
Wazuh provides out-of-the-box active responses to perform various countermeasures to address active threats, such as blocking access to a system from the threat source when certain criteria are met.
In addition, Wazuh can be used to remotely run commands or system queries, identifying indicators of compromise (IOCs) and helping perform other live forensics or incident response tasks.

#### Regulatory Compliance
Wazuh provides some of the necessary security controls to become compliant with industry standards and regulations. These features, combined with its scalability and multi-platform support help organizations meet technical compliance requirements.
Wazuh is widely used by payment processing companies and financial institutions to meet PCI DSS (Payment Card Industry Data Security Standard) requirements. Its web user interface provides reports and dashboards that can help with this and other regulations (e.g. GPG13 or GDPR).

#### Cloud Security Monitoring
Wazuh helps monitoring cloud infrastructure at an API level, using integration modules that are able to pull security data from well known cloud providers, such as Amazon AWS, Azure or Google Cloud. In addition, Wazuh provides rules to assess the configuration of your cloud environment, easily spotting weaknesses.
In addition, Wazuh light-weight and multi-platform agents are commonly used to monitor cloud environments at the instance level.

#### Containers Security
Wazuh provides security visibility into your Docker hosts and containers, monitoring their behavior and detecting threats, vulnerabilities and anomalies. The Wazuh agent has native integration with the Docker engine allowing users to monitor images, volumes, network settings, and running containers.
Wazuh continuously collects and analyzes detailed runtime information. For example, alerting for containers running in privileged mode, vulnerable applications, a shell running in a container, changes to persistent volumes or images, and other possible threats.

### Architecture
<p><img src="https://raw.githubusercontent.com/goldstrike77/Screenshots/master/Wazuh/architecture_ports_elastic1.png" /></p>

## Requirements
### Operating systems
Wazuh is available for most operating systems like Linux, OpenBSD, macOS, Solaris, Windows and FreeBSD. In this Ansible role, we will take you through how to guide on CentOS/RedHat Linux server.

On only one data node cluster environment, .wazuh & .wazuh-version indices health status will changed from GREEN to YELLOW because have 1 replicas after the first start, Unfortunately, I really don't know why.

Steps to fix this problem:

1. Delete the .wazuh and .wazuh-version indices.
2. Restart the kibana service.
3. Re-connect your API entries on the Wazuh app.

Please confirm there is a suitable version of Wazuh app, and fix internet connection problems on some area under GFW.

for example:
http://cache.omygods.com/wazuhapp/wazuhapp-3.9.5_7.2.1.zip / http://packages.wazuh.com/wazuhapp/wazuhapp-3.9.5_7.2.1.zip

This role will work on the following operating systems:

  * CentOS 7

### Wazuh versions

The following list of supported the wazuh releases:

  * 3.12.3+

## Role variables
### Main parameters #
There are some variables in defaults/main.yml which can (Or needs to) be overridden:

##### General parameters
* `ossec_version`: Specify the Wazuh version.
* `ossec_selinux`: SELinux security policy.
* `ossec_authd_pass`: Agent verification password.
* `ossec_api_user`: API verification username.
* `ossec_api_pass`: API verification password.
* `ossec_cluster`: Specifies the name of the cluster.
* `ossec_path`: Specify the OSSec data directory.

##### Role dependencies
* `ossec_elastic_stack_dept`: A boolean value, whether Elastic Stack components use the same environment.

##### Mail parameters
* `ossec_mail_arg`: Mail system parameters.

##### Elastic Stack parameters
* `ossec_elastic_stack_auth`: A boolean value, Enable or Disable authentication.
* `ossec_elastic_stack_user`: Authorization user name, do not modify it.
* `ossec_elastic_stack_pass`: Authorization user password.
* `ossec_elastic_stack_version`: Specify the Elastic Stack version.
* `ossec_elastic_port`: Elasticsearch REST port.
* `ossec_elastic_heap_size`: Specify the maximum memory allocation pool for a Java virtual machine.
* `ossec_elastic_path`: Specify the ElasticSearch data directory.
* `ossec_elastic_node_type`: Type of nodes`: default, master, data, ingest and coordinat.
* `ossec_kibana_port`: Kibana server port.
* `ossec_kibana_proxy`: Whether running behind a HaProxy.
* `ossec_kibana_ngx_dept`: Whether proxy web interface and API traffic using NGinx.
* `ossec_kibana_ngx_domain`: Defines domain name.
* `ossec_kibana_ngx_port_http`: NGinx HTTP listen port.
* `ossec_kibana_ngx_port_https`: NGinx HTTPs listen port.
* `ossec_kibana_ngx_site_path`: Specify the NGinx site directory.
* `ossec_kibana_ngx_logs_path`: Specify the NGinx logs directory.

##### Listen port #
* `ossec_port_arg`: Network ports for OSSec components.

##### Cluster parameters
* `ossec_cluster_arg`: Cluster system parameters.

##### System Variables
* `ossec_manager_config`: Manager system parameters.
* `ossec_agent_configs`: Shared agent configuration.
* `ossec_agentless_creds`: Integrity checks on systems without an agent installed.

##### Service Mesh
* `environments`: Define the service environment.
* `tags`: Define the service custom label.

### Other parameters
There are some variables in vars/main.yml:

## Dependencies
- Ansible versions >= 2.8
- Python >= 2.7.5
- [NGinx](https://github.com/goldstrike77/ansible-role-linux-nginx.git)
- [Elasticsearch](https://github.com/goldstrike77/ansible-role-linux-elasticsearch.git)
- [Kibana](https://github.com/goldstrike77/ansible-role-linux-kibana.git)
- [Beats](https://github.com/goldstrike77/ansible-role-OS-beats.git)

## Example

### Hosts inventory file
See tests/inventory for an example.

    node01 ansible_host='192.168.1.10' ossec_version='3.12.3-1'

### Vars in role configuration
Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: all
      roles:
         - role: ansible-role-linux-ossec
           ossec_version: '3.12.3-1'

### Combination of group vars and playbook
You can also use the group_vars or the host_vars files for setting the variables needed for this role. File you should change: group_vars/all or host_vars/`group_name`

    ossec_version: '3.12.3-1'
    ossec_authd_pass: 'Bf6vJRT4WaEAHq'
    ossec_api_user: 'admin'
    ossec_api_pass: 'changeme'
    ossec_cluster: 'ossec'
    ossec_path: '/data'
    ossec_elastic_stack_dept: true
    ossec_mail_arg:
      email_alert_level: '12'
      email_from: 'ossec@example.com'
      email_maxperhour: '12'
      email_notification: 'yes'
      email_to:
        - 'somebody@example.com'
      smtp_server: 'localhost'
    ossec_elastic_stack_auth: true
    ossec_elastic_stack_user: 'elastic'
    ossec_elastic_stack_pass: 'changeme'
    ossec_elastic_stack_version: '7.6.2'
    ossec_elastic_port: '9200'
    ossec_elastic_heap_size: '3g'
    ossec_elastic_path: '{{ ossec_path }}'
    ossec_elastic_node_type: 'default'
    ossec_kibana_port: '5601'
    ossec_kibana_proxy: false
    ossec_kibana_ngx_dept: false
    ossec_kibana_ngx_domain: 'navigate.example.com'
    ossec_kibana_ngx_port_http: '80'
    ossec_kibana_ngx_port_https: '443'
    ossec_kibana_ngx_site_path: '{{ ossec_path }}/nginx_site'
    ossec_kibana_ngx_logs_path: '{{ ossec_path }}/nginx_logs'
    ossec_port_arg:
      agent: '1517'
      api: '55000'
      cluster: '1516'
      register: '1515'
      syslog: '514'
    ossec_cluster_arg:
      hidden: 'no'
    ossec_manager_config:
      elastic_rotate_day: '180'
      archive_rotate_day: '10'
      max_output_size: '50M'
      alerts_log: 'yes'
      jsonout_output: 'yes'
      logall: 'no'
      logall_json: 'no'
      log_format: 'plain'
      log_alert_level: 1
      syslog_outputs:
        - server: null
          port: null
          format: null
      white_list:
        - '127.0.0.1'
        - '^localhost.localdomain$'
        - '223.5.5.5'
        - '223.6.6.6'
        - '8.8.8.8'
      commands:
        - name: 'disable-account'
          executable: 'disable-account.sh'
          expect: 'user'
          timeout_allowed: 'yes'
        - name: 'restart-ossec'
          executable: 'restart-ossec.sh'
          expect: 'srcip'
          timeout_allowed: 'yes'
        - name: 'firewall-drop'
          executable: 'firewall-drop.sh'
          expect: 'srcip'
          timeout_allowed: 'yes'
        - name: 'host-deny'
          executable: 'host-deny.sh'
          expect: 'srcip'
          timeout_allowed: 'yes'
        - name: 'route-null'
          executable: 'route-null.sh'
          expect: 'srcip'
          timeout_allowed: 'yes'
        - name: 'win_route-null'
          executable: 'route-null.cmd'
          expect: 'srcip'
          timeout_allowed: 'yes'
        - name: 'win_route-null-2012'
          executable: 'route-null-2012.cmd'
          expect: 'srcip'
          timeout_allowed: 'yes'
        - name: 'netsh'
          executable: 'netsh.cmd'
          expect: 'srcip'
          timeout_allowed: 'yes'
        - name: 'netsh-win-2016'
          executable: 'netsh-win-2016.cmd'
          expect: 'srcip'
          timeout_allowed: 'yes'
      remote:
        - type: 'secure'
          port: '{{ ossec_port_arg.agent }}'
          protocol: 'tcp'
          ipv6: 'no'
      rootcheck:
        disable: 'yes'
      openscap:
        disable: 'no'
        timeout: 1800
        interval: '1d'
        scan_on_start: 'no'
      osquery:
        disable: 'no'
        run_daemon: 'yes'
        log_path: '/var/log/osquery/osqueryd.results.log'
        config_path: '/etc/osquery/osquery.conf'
        ad_labels: 'yes'
      syscollector:
        disable: 'no'
        interval: '1d'
        scan_on_start: 'no'
        hardware: 'yes'
        os: 'yes'
        network: 'yes'
        packages: 'yes'
        ports_no: 'yes'
        processes: 'yes'
      localfiles:
        common:
          - format: 'command'
            command: 'df -P -x squashfs -x tmpfs -x devtmpfs'
            frequency: '360'
          - format: 'full_command'
            command: "ss -nutal | awk '{print $1,$5,$6;}' | sort -b | column -t"
            alias: 'netstat listening ports'
            frequency: '360'
          - format: 'full_command'
            command: 'last -n 20'
          - format: 'syslog'
            location: '/var/ossec/logs/active-responses.log'
        debian:
          - format: 'syslog'
            location: '/var/log/auth.log'
          - format: 'syslog'
            location: '/var/log/syslog'
          - format: 'syslog'
            location: '/var/log/dpkg.log'
          - format: 'syslog'
            location: '/var/log/kern.log'
        centos:
          - format: 'syslog'
            location: '/var/log/messages'
          - format: 'syslog'
            location: '/var/log/secure'
          - format: 'syslog'
            location: '/var/log/maillog'
          - format: 'audit'
            location: '/var/log/audit/audit.log'
      vul_detector:
        enabled: 'yes'
        interval: '1d'
        ignore_time: '6h'
        run_on_start: 'no'
        redhat:
          enabled: 'yes'
          update_interval: '1d'
      syscheck:
        disable: 'no'
        frequency: 86400
        scan_on_start: 'no'
        auto_ignore: 'no'
        alert_new_files: 'yes'
        ignore:
          - '/etc/mtab'
          - '/etc/hosts.deny'
          - '/etc/mail/statistics'
          - '/etc/random-seed'
          - '/etc/random.seed'
          - '/etc/adjtime'
          - '/etc/httpd/logs'
          - '/etc/utmpx'
          - '/etc/wtmpx'
          - '/etc/cups/certs'
          - '/etc/dumpdates'
          - '/etc/svc/volatile'
          - '/sys/kernel/security'
          - '/sys/kernel/debug'
        no_diff:
          - '/etc/ssl/private.key'
      reports:
        - enable: true
          category: 'syscheck'
          title: 'Daily report: File changes'
          email_to: '{{ ossec_mail_arg.email_to }}'    
      api:
        https: 'yes'
        basic_auth: 'yes'
        behind_proxy_server: 'no'
        https_cert: '/var/ossec/etc/sslmanager.cert'
        https_key: '/var/ossec/etc/sslmanager.key'
        https_use_ca: 'no'
        https_ca: ''
        use_only_authd: 'false'
        drop_privileges: 'true'
        experimental_features: 'false'
        secure_protocol: 'TLSv1_2_method'
        honor_cipher_order: 'true'
        ciphers: ''
      authd:
        disable: 'no'
        use_source_ip: 'no'
        force_insert: 'yes'
        force_time: 0
        purge: 'no'
        use_password: 'yes'
        ssl_agent_ca: null
        ssl_verify_host: 'no'
        ssl_manager_cert: '/var/ossec/etc/sslmanager.cert'
        ssl_manager_key: '/var/ossec/etc/sslmanager.key'
        ssl_auto_negotiate: 'no'
    ossec_agent_configs:
      - type: 'os'
        type_value: 'Linux'
        syscheck:
          disable: 'no'
          frequency: '86400'
          scan_on_start: 'yes'
          auto_ignore: 'no'
          alert_new_files: 'yes'
          remove_old_diff: 'yes'
          ignore:
            - '/etc/mtab'
            - '/etc/hosts.deny'
            - '/etc/mail/statistics'
            - '/etc/random-seed'
            - '/etc/random.seed'
            - '/etc/adjtime'
            - '/etc/httpd/logs'
            - '/etc/utmpx'
            - '/etc/wtmpx'
            - '/etc/cups/certs'
            - '/etc/dumpdates'
            - '/etc/svc/volatile'
            - '/sys/kernel/security'
            - '/sys/kernel/debug'
          no_diff:
            - '/etc/ssl/private.key'
          directories:
            - dirs: '/etc'
              whodata: 'yes'
            - dirs: '/bin,/sbin,/usr/bin,/usr/sbin'
            - dirs: '/usr/local/sbin,/usr/local/bin'
        rootcheck:
          disable: 'yes'
        localfiles:
          - format: 'syslog'
            location: '/var/log/messages'
          - format: 'syslog'
            location: '/var/log/secure'
          - format: 'syslog'
            location: '/var/log/maillog'
          - format: 'audit'
            location: '/var/log/audit/audit.log'
          - format: 'syslog'
            location: '/var/ossec/logs/active-responses.log'
          - format: 'command'
            command: 'df -P -x squashfs -x tmpfs -x devtmpfs'
            frequency: '360'
          - format: 'full_command'
            command: "ss -nutal | awk '{print $1,$5,$6;}' | sort -b | column -t"
            alias: 'netstat listening ports'
            frequency: '360'
          - format: 'full_command'
            command: 'last -n 20'
            frequency: '360'
        syscollector:
          disable: 'no'
          interval: '1d'
          scan_on_start: 'yes'
          hardware: 'yes'
          os: 'yes'
          network: 'yes'
          packages: 'yes'
          ports: 'yes'
          processes: 'yes'
        osquery:
          disable: 'no'
          run_daemon: 'yes'
          add_labels: 'yes'
        client_buffer:
          disable: 'no'
          queue_size: '5000'
          events_per_sec: '500'
        sca:
          enabled: 'yes'
          scan_on_start: 'yes'
          skip_nfs: 'yes'
          interval: '1d'
          policies:
            - 'cis_rhel7_linux_rcl.yml'
            - 'system_audit_pw.yml'
            - 'system_audit_rcl.yml'
            - 'system_audit_ssh.yml'
      - type: 'os'
        type_value: 'Windows'
        syscheck:
          disable: 'no'
          frequency: '86400'
          scan_on_start: 'yes'
          auto_ignore: 'no'
          alert_new_files: 'yes'
          remove_old_diff: 'yes'
          win_audit_interval: '300'
          ignore:
            - '.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$'
          directories:
            - dirs: '%WINDIR%\regedit.exe'
            - dirs: '%WINDIR%\system.ini'
            - dirs: '%WINDIR%\win.ini'
            - dirs: '%WINDIR%\SysNative\at.exe'
            - dirs: '%WINDIR%\SysNative\attrib.exe'
            - dirs: '%WINDIR%\SysNative\cacls.exe'
            - dirs: '%WINDIR%\SysNative\cmd.exe'
            - dirs: '%WINDIR%\SysNative\drivers\etc'
            - dirs: '%WINDIR%\SysNative\eventcreate.exe'
            - dirs: '%WINDIR%\SysNative\ftp.exe'
            - dirs: '%WINDIR%\SysNative\lsass.exe'
            - dirs: '%WINDIR%\SysNative\net.exe'
            - dirs: '%WINDIR%\SysNative\net1.exe'
            - dirs: '%WINDIR%\SysNative\netsh.exe'
            - dirs: '%WINDIR%\SysNative\reg.exe'
            - dirs: '%WINDIR%\SysNative\regedt32.exe'
            - dirs: '%WINDIR%\SysNative\regsvr32.exe'
            - dirs: '%WINDIR%\SysNative\runas.exe'
            - dirs: '%WINDIR%\SysNative\sc.exe'
            - dirs: '%WINDIR%\SysNative\schtasks.exe'
            - dirs: '%WINDIR%\SysNative\sethc.exe'
            - dirs: '%WINDIR%\SysNative\subst.exe'
            - dirs: '%WINDIR%\SysNative\wbem\WMIC.exe'
            - dirs: '%WINDIR%\SysNative\WindowsPowerShell\v1.0\powershell.exe'
            - dirs: '%WINDIR%\SysNative\winrm.vbs'
            - dirs: '%WINDIR%\System32\at.exe'
            - dirs: '%WINDIR%\System32\attrib.exe'
            - dirs: '%WINDIR%\System32\cacls.exe'
            - dirs: '%WINDIR%\System32\cmd.exe'
            - dirs: '%WINDIR%\System32\drivers\etc'
            - dirs: '%WINDIR%\System32\eventcreate.exe'
            - dirs: '%WINDIR%\System32\ftp.exe'
            - dirs: '%WINDIR%\System32\net.exe'
            - dirs: '%WINDIR%\System32\net1.exe'
            - dirs: '%WINDIR%\System32\netsh.exe'
            - dirs: '%WINDIR%\System32\reg.exe'
            - dirs: '%WINDIR%\System32\regedit.exe'
            - dirs: '%WINDIR%\System32\regedt32.exe'
            - dirs: '%WINDIR%\System32\regsvr32.exe'
            - dirs: '%WINDIR%\System32\runas.exe'
            - dirs: '%WINDIR%\System32\sc.exe'
            - dirs: '%WINDIR%\System32\schtasks.exe'
            - dirs: '%WINDIR%\System32\sethc.exe'
            - dirs: '%WINDIR%\System32\subst.exe'
            - dirs: '%WINDIR%\System32\wbem\WMIC.exe'
            - dirs: '%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe'
            - dirs: '%WINDIR%\System32\winrm.vbs'
            - dirs: '%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup'
          registry:
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\batfile'
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\cmdfile'
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\comfile'
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\exefile'
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\piffile'
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\AllFilesystemObjects'
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\Directory'
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\Folder'
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\Protocols'
              arch: "both"
            - key: 'HKEY_LOCAL_MACHINE\Software\Policies'
              arch: "both"
            - key: 'HKEY_LOCAL_MACHINE\Security'
            - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer'
              arch: "both"
            - key: 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services'
            - key: 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\KnownDLLs'
            - key: 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\winreg'
            - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
              arch: "both"
            - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
              arch: "both"
            - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
            - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\URL'
              arch: "both"
            - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies'
              arch: "both"
            - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows'
              arch: "both"
            - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
              arch: "both"
            - key: 'HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components'
              arch: "both"
          registry_ignore:
            - key: 'HKEY_LOCAL_MACHINE\Security\Policy\Secrets'
            - key: 'HKEY_LOCAL_MACHINE\Security\SAM\Domains\Account\Users'
            - key: '\Enum$'
              type: "sregex"
        rootcheck:
          disable: 'yes'
        localfiles:
          - format: 'eventlog'
            location: 'Application'
          - format: 'eventchannel'
            location: 'Security'
            query: 'Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907]'
          - format: 'eventlog'
            location: 'System'
          - format: 'syslog'
            location: 'active-response\active-responses.log'
        syscollector:
          disable: 'no'
          interval: '1d'
          scan_on_start: 'yes'
          hardware: 'yes'
          os: 'yes'
          network: 'yes'
          packages: 'yes'
          ports: 'yes'
          processes: 'yes'
        osquery:
          disable: 'no'
          run_daemon: 'yes'
          add_labels: 'yes'
        client_buffer:
          disable: 'no'
          queue_size: '5000'
          events_per_sec: '500'
        sca:
          enabled: 'yes'
          scan_on_start: 'yes'
          skip_nfs: 'yes'
          interval: '1d'
          policies:
            - 'win_audit_rcl.yml'
    ossec_agentless_creds:
      - type: 'ssh_integrity_check_linux'
        frequency: 3600
        host: 'root@example.net'
        state: 'periodic'
        arguments: '/bin /etc/ /sbin'
        passwd: 'qwerty'
    environments: 'Development'
    tags:
      subscription: 'default'
      owner: 'nobody'
      department: 'Infrastructure'
      organization: 'The Company'
      region: 'IDC01'

## License
![](https://img.shields.io/badge/MIT-purple.svg?style=for-the-badge)

## Author Information
Please send your suggestions to make this role better.

## Contributors
Special thanks to the [Connext Information Technology](http://www.connext.com.cn) for their contributions to this role.
