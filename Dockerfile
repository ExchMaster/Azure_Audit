FROM centos:7
LABEL maintainer="jingram@microsoft.com"
WORKDIR /azRBACAudit
COPY ./bin/Debug/netcoreapp2.1/publish/ /azRBACAudit
ENV AZURE_AUTH_LOCATION=/azRBACAudit/AzureAuth.properties
RUN rpm -Uvh https://packages.microsoft.com/config/rhel/7/packages-microsoft-prod.rpm
RUN yum update -y
RUN yum install dotnet-runtime-2.1 -y

CMD ["dotnet","azrbacaudit.dll","&"]