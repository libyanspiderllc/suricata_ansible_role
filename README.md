Suricata Ansible Role
=========

Ansible role to install and configure [Suricata](https://suricata.readthedocs.io/en/suricata-6.0.2/what-is-suricata.html) NIDS (v6.x).

Tested with: 
- CentOS 7
- CloudLinux 7
- CentOS 8
- Rocky Linux 8
- AlmaLinux 8
- AlmaLinux 9

Requirements
------------

None

Role Variables
--------------

None

Dependencies
------------

None

Example Playbook
----------------

    - hosts: servers
      roles:
         - { role: libyanspider.suricata_ansible_role }

License
-------

BSD

Author Information
------------------

Ahmed Shibani (#shumbashi)
sheipani@gmail.com
