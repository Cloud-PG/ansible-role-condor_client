FROM centos:7

RUN yum install epel-release \
       && yum install ansible \
       && printf '[defaults]\nroles_path=../' > ansible.cfg
