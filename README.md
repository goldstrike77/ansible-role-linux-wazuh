![](https://img.shields.io/badge/Ansible-ossec-green.svg?logo=angular&style=for-the-badge)

>__Please note that the original design goal of this role was more concerned with the initial installation and bootstrapping environment, which currently does not involve performing continuous maintenance, and therefore are only suitable for testing and development purposes,  should not be used in production environments.__

>__请注意，此角色的最初设计目标更关注初始安装和引导环境，目前不涉及执行连续维护，因此仅适用于测试和开发目的，不应在生产环境中使用。__
___

<p><img src="https://raw.githubusercontent.com/goldstrike77/goldstrike77.github.io/master/img/logo/logo_wazuh.png" align="right" /></p>

__Table of Contents__

- [Overview](#overview)
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
This Ansible role installs Wazuh manager on linux operating system, including establishing a filesystem structure and server configuration with some common operational features.

## Requirements
### Operating systems
This role will work on the following operating systems:

  * CentOS 7

### Wazuh versions

The following list of supported the wazuh releases:

  * 3.9.2

## Role variables
### Main parameters #
There are some variables in defaults/main.yml which can (Or needs to) be overridden:

##### General parameters
* `ossec_version`: Specify the Wazuh version.
* `ossec_selinux`: SELinux security policy.
* `ossec_authd_pass`: Agent verification password.
* `ossec_api_user`: API verification password.
* `ossec_cluster`: Specifies the name of the cluster.

##### Role dependencies
* `ossec_elastic_stack_dept`: A boolean value, whether Elastic Stack components use the same environment.

##### Mail parameters
* `ossec_mail_arg.email_alert_level`: The minimum severity level for an alert to generate an email notification.
* `ossec_mail_arg.email_from`: Specifies the source address contained in the email alerts.
* `ossec_mail_arg.email_maxperhour`: The maximum number of email alerts that can be sent per hour.
* `ossec_mail_arg.email_notification`: Toggles the use of email alerting.
* `ossec_mail_arg.email_to`: Specifies the email recipient list for alerts.
* `ossec_mail_arg.smtp_server`: Defines what SMTP server to use to deliver alerts.

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
* `ossec_kibana_ngx_domain`: Defines domain name.
* `ossec_kibana_ngx_port_http`: NGinx HTTP listen port.
* `ossec_kibana_ngx_port_https`: NGinx HTTPs listen port.
* `ossec_kibana_ngx_site_path`: Specify the NGinx site directory.
* `ossec_kibana_ngx_logs_path`: Specify the NGinx logs directory.

##### Listen port
* `ossec_port_arg`: Network ports for OSSEC components.

##### Cluster parameters
* `ossec_cluster_arg.interval`: The interval between cluster synchronizations.
* `ossec_cluster_arg.hidden`: Whether or not to show information about the cluster that generated an alert.

##### System Variables
* `ossec_manager_config.queue_size`: Sets the size of the message input buffer in Analysisd (number of events).
* `ossec_manager_config.max_output_size`: The size limit of alert files with a maximum allowed value.
* `ossec_manager_config.alerts_log`: Toggles the writing of alerts to /var/ossec/logs/alerts/alerts.log.
* `ossec_manager_config.jsonout_output`: Toggles the writing of JSON-formatted alerts to /var/ossec/logs/alerts/alerts.json.
* `ossec_manager_config.logall`: Whether to store events even when they do not trip a rule with results written to /var/ossec/logs/archives/archives.log.
* `ossec_manager_config.logall_json`: Whether to store events even when they do not trip a rule with results written to /var/ossec/logs/archives/archives.json.
* `ossec_manager_config.log_format`: Specifies the log format between JSON output or plain text.
* `ossec_manager_config.log_alert_level`: The minimum severity level for alerts that will be stored to alerts.log and/or alerts.json.
* `ossec_manager_config.labels`: Allows additional user-defined information about agents to be included in alerts.
* `ossec_manager_config.syslog_outputs`: Options for sending alerts to a syslog server.
* `ossec_manager_config.white_list`: IP addresses that should never be blocked with an active response.
* `ossec_manager_config.commands`: Defined that will be used by one or more active responses.
* `ossec_manager_config.connection`: Listen for events from the agents.
* `ossec_manager_config.rootcheck`: Policy monitoring and anomaly detection.
* `ossec_manager_config.openscap`: Configuration and vulnerability scans of an agent.
* `ossec_manager_config.osquery`: Osquery configuration and collect the information.
* `ossec_manager_config.syscollector`: Collect interesting system information.
* `ossec_manager_config.localfiles`: Collection of log data from files.
* `ossec_manager_config.vul_detector`: Detect applications that are known to be vulnerable (affected by a CVE).
* `ossec_manager_config.syscheck`: File integrity monitoring.
* `ossec_manager_config.reports`: Daily reports are summaries of the alerts that were triggered each day.
* `ossec_manager_config.api`: RESTful API configuration.
* `ossec_manager_config.authd`: Client authorization.
* `ossec_agent_configs`: Shared agent configuration.
* `ossec_agentless_creds`: Integrity checks on systems without an agent installed.

### Other parameters
There are some variables in vars/main.yml:

## Dependencies
- Ansible versions > 2.6 are supported.
- [NGinx](https://github.com/goldstrike77/ansible-role-linux-nginx.git)
- [Elasticsearch](https://github.com/goldstrike77/ansible-role-linux-elasticsearch.git)
- [Kibana](https://github.com/goldstrike77/ansible-role-linux-kibana.git)
- [Filebeat](https://github.com/goldstrike77/ansible-role-linux-filebeat.git)

## Example

### Hosts inventory file
See tests/inventory for an example.

    node01 ansible_host='192.168.1.10' ossec_version='3.9.2-1'

### Vars in role configuration
Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: all
      roles:
         - role: ansible-role-linux-ossec
           ossec_version: '3.9.2-1'

### Combination of group vars and playbook
You can also use the group_vars or the host_vars files for setting the variables needed for this role. File you should change: group_vars/all or host_vars/`group_name`

    ossec_version: '3.9.2-1'
    ossec_selinux: false
    ossec_authd_pass: 'Bf6vJRT4WaEAHq'
    ossec_api_user: "admin:$apr1$COfllHXr$Dz5U9s8/kwKlf9XxmMGp61"
    ossec_cluster: 'ossec'
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
    ossec_elastic_stack_version: '7.1.1'
    ossec_elastic_port: '9200'
    ossec_elastic_heap_size: '3g'
    ossec_elastic_path: '/data'
    ossec_elastic_node_type: 'default'
    ossec_kibana_port: '5601'
    ossec_kibana_ngx_domain: 'navigate.example.com'
    ossec_kibana_ngx_port_http: '80'
    ossec_kibana_ngx_port_https: '443'
    ossec_kibana_ngx_site_path: '/data/nginx_site'
    ossec_kibana_ngx_logs_path: '/data/nginx_logs'
    ossec_port_arg:
      agent: '1514'
      api: '55000'
      cluster: '1516'
      register: '1515'
      syslog: '514'
    ossec_cluster_arg:
      interval: '60s'
      hidden: 'no'
    ossec_manager_config:
      queue_size: '131072'
      max_output_size: '50M'
      alerts_log: 'yes'
      jsonout_output: 'yes'
      logall: 'no'
      logall_json: 'no'
      log_format: 'plain'
      log_alert_level: 1
      labels:
        enable: true
        list:
          - key: 'Environments'
            value: 'Production'
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
      connection:
        - type: 'secure'
          port: '{{ ossec_port_arg.agent }}'
          protocol: 'udp'
          queue_size: 131072
      rootcheck:
        disable: 'no'
        check_unixaudit: 'yes'
        check_files: 'yes'
        check_trojans: 'yes'
        check_dev: 'yes'
        check_sys: 'yes'
        check_pids: 'yes'
        check_ports: 'yes'
        check_if: 'yes'
        skip_nfs: 'yes'
        frequency: 43200
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
        disable: 'no'
        interval: '1d'
        ignore_time: '6h'
        run_on_start: 'no'
        ubuntu:
          disable: 'yes'
          update_interval: '1d'
        redhat:
          disable: 'no'
          update_interval: '1d'
        debian:
          disable: 'yes'
          update_interval: '1d'
      syscheck:
        disable: 'no'
        frequency: 43200
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
        enable: true
        use_source_ip: 'yes'
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
          frequency: 43200
          scan_on_start: 'no'
          auto_ignore: 'no'
          alert_new_files: 'yes'
          ignore:
            - '/etc/mtab'
            - '/etc/mnttab'
            - '/etc/hosts.deny'
            - '/etc/mail/statistics'
            - '/etc/svc/volatile'
          no_diff:
            - '/etc/ssl/private.key'
        rootcheck:
          frequency: 43200
          cis_distribution_filename: null
        localfiles:
          - format: 'syslog'
            location: '/var/log/messages'
          - format: 'syslog'
            location: '/var/log/secure'
      - type: 'os'
        type_value: 'Windows'
        syscheck:
          frequency: 43200
          scan_on_start: 'no'
          auto_ignore: 'no'
          alert_new_files: 'yes'
          windows_registry:
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\batfile'
              arch: 'both'
            - key: 'HKEY_LOCAL_MACHINE\Software\Classes\Folder'
        localfiles:
          - location: 'Security'
            format: 'eventchannel'
          - location: 'System'
            format: 'eventlog'
    ossec_agentless_creds:
      type: 'ssh_integrity_check_linux'
      frequency: 3600
      host: 'root@example.net'
      state: 'periodic'
      arguments: '/bin /etc/ /sbin'
      passwd: 'qwerty'

## License
![](https://img.shields.io/badge/MIT-purple.svg?style=for-the-badge)

## Author Information
Please send your suggestions to make this role better.

## Contributors
Special thanks to the [Connext Information Technology](http://www.connext.com.cn) for their contributions to this role.
