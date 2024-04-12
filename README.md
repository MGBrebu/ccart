# Cisco Configuration Auditing and Reporting Tool
CLI Python utility that aims to automatically audit a provided Cisco network device configuration file and generate a report providing device information, potential security flaws, and recommended remediations.

Provides the backend functionality for the greater [Configuroo](https://github.com/DanB983/Configuroo) auditing web application but can be used as a standalone CLI utility.

### Requires
* Python 3.x
* [ciscoconfparse](https://pypi.org/project/ciscoconfparse/)  

### Usage
1. Run using `python .\ccart.py` in local context
2. (*Optional*) Run `python .\clearOut.py` to remove any reports generated in `.\output`
