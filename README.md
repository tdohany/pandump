# pandump
Utilities to dump PAN-OS information into comma-delimited output.

- secdump.py: Dump firewall security rules (pre/local/post/default) into CSV formatted output
- natdump.py: Dump firewall NAT rules (pre/local/post) into CSV formatted output
- devdump.py: Dump Panorama managed devices into CSV formatted output
- licdump.py: Dump Panorama licensing for managed devices into CSV formatted output

## Features
- Policy output reflects resultant set of pre, local, post, and default rules
- Support for .panrc tags and API key mapping
- Interactive password prompt if not supplied in command line arguments
- Displays results to sys.stdout if no output file is specified

## Installation
```
$ git clone https://github.com/stealthllama/pandump.git
$ cd pandump
$ virtualenv venv
$ source venv/bin/activate
(venv) $ pip install -r requirements.txt
```

## Usage
```
(venv) $ secdump.py [-h] [-u USERNAME] [-p PASSWORD] [-f FIREWALL] [-t TAG] [-o OUTFILE]
(venv) $ natdump.py [-h] [-u USERNAME] [-p PASSWORD] [-f FIREWALL] [-t TAG] [-o OUTFILE]
(venv) $ devdump.py [-h] [-u USERNAME] [-p PASSWORD] [-m PANORAMA] [-t TAG] [-o OUTFILE]
(venv) $ licdump.py [-h] [-u USERNAME] [-p PASSWORD] [-m PANORAMA] [-t TAG] [-o OUTFILE]
```
