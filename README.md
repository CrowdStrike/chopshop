CrowdStrike ChopShop Modules
========

ChopShop is a MITRE developed framework to aid analysts in the creation and execution of pynids based decoders and detectors of APT tradecraft.

Note that ChopShop is still in perpetual beta and is dependent on libnids/pynids for the majority of its underlying functionality.

Documentation for ChopShop can be found on
[ReadTheDocs](https://chopshop.readthedocs.org/).

Description
-----------
This repository contains ChopShop Modules written by CrowdStrike. The documentation for each module is contained [module documentation](https://github.com/CrowdStrike/chopshop/tree/master/docs/module_docs).

Module Installation
-----------
- Grab MITRE's ChopShop network decoder framework from https://github.com/MITRECND/chopshop
- Chopshop's HTTP module requires Python library htpy, you can grab it on MITRE's Github https://github.com/MITRECND/htpy
- Copy over the .py module file to chopshop/modules/ directory.

Bugs can be report to [William Tan](william.tan@crowdstrike.com)
