![pypi](https://img.shields.io/pypi/v/vtscan.svg)
![python](https://img.shields.io/pypi/pyversions/vtscan.svg)
![docs](https://readthedocs.org/projects/vtscan/badge/?version=latest)
![license](https://img.shields.io/github/license/prahladyeri/vtscan.svg)
![last-commit](https://img.shields.io/github/last-commit/prahladyeri/vtscan.svg)
[![patreon](https://img.shields.io/badge/Patreon-brown.svg?logo=patreon)](https://www.patreon.com/prahladyeri)
[![paypal](https://img.shields.io/badge/PayPal-blue.svg?logo=paypal)](https://paypal.me/prahladyeri)
[![follow](https://img.shields.io/twitter/follow/prahladyeri.svg?style=social)](https://twitter.com/prahladyeri)

# vtscan

Command line tool to scan for malicious files using the VirusTotal API

# Installation

	pip install vtscan

# Usage

```bash
C:\> vtscan c:\programs\FileZilla-3.44.0\filezilla.exe
calculating sha1 hash...
done. sending scan request...

Found in VT Database
permalink:  https://www.virustotal.com/gui/file/9bbf15a489e7e109f8e238013846a29448c7994a46b7507be239a2aeeccf99f7/detection/f-9bbf15a489e7e109f8e238013846a29448c7994a46b7507be239a2aeeccf99f7-1656398328
Number of positives: 0 (out of 66 scanners applied)
verbose_msg: Scan finished, information embedded
7a37556cc8d665b508dd118fb3baec27b7891fb1 is not malicious

done

C:\>
```

# Notes

You'll need a VirusTotal API key to use this program, you can get one by registering a free account at [www.virustotal.com](https://www.virustotal.com). Once you have the API key, you can just put it in the `%userprofile%\.config\vtscan-settings.json` directory.


## Donation

Please consider donating if this tool has helped you in any way.

- [Donate through PayPal](https://www.paypal.me/prahladyeri)
- [Donate through Patreon](https://www.patreon.com/prahladyeri)

You can also hire me through [Upwork](https://www.upwork.com/freelancers/~01e977ff45b62e031c) or [Fiverr](https://www.fiverr.com/prahladyeri) or [contact me directly](mailto:prahladyeri@yahoo.com) to get professional support and customization.