# Security Threat Intelligence Add-On for Splunk - Source Code

This repository contains source code vital to the function of my Final Year Project. These include

- Splunk Alerts and Ingestion Scripts
- TA-datainputs, which contains the config files used for my add-on

These scripts and config files are used for for ingesting threat intelligence data from various sources and implementing automated alert actions in a Splunk environment.

## Repository Structure Overview

The Alerts and Ingestion Scripts folder consists of two main components:

1. **Ingestion Scripts**: Python scripts that collect threat intelligence data from external APIs and ingest it into Splunk.
2. **Alert Action Scripts**: Scripts that take action based on Splunk alerts, such as sending email notifications when threats are detected.

The TA-datainputs folder consits of the following main componets:

1. **.config files**: These are the main files that are used to configure important details regarding this add-on. Details such as data ingestion intervals, sourcetypes and files regarding the packaging of this app when its posted to SplunkBase.
2. **General Miscellaneous Files**: These are small files contain metadata and other small, less important pieces of information. These files are still important in the running of the add-on and can be configured by the user or organiation who uses.
