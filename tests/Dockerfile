FROM centos:7

RUN yum install -y epel-release \
       && yum -y install ansible \
       && printf '[defaults]\nroles_path=../' > ansible.cfg
