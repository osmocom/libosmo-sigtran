libosmo-sigtran - Osmocom SCCP, SIGTRAN and STP
============================================

This repository contains

* *libosmo-sigtran*, a C-language library implementation of a variety of telecom signaling protocols, such as M3UA, SUA, SCCP
  (connection oriented and connectionless)
* *OsmoSTP*, a SS7 Transfer Point that can be used to act as router and translator between M3UA, SUA and/or
  SCCPlite

The code in this repository used to be in *libosmo-sccp.git*, together with the legacy C-language static library
*libosmo-sccp*. This library was used in prehistoric Osmocom code before we had libosmo-sigtran. If you need to compile
old code that requires libosmo-sccp, use [libosmo-sccp-legacy](https://gitea.osmocom.org/osmocom/libosmo-sccp-legacy).

Homepage
--------

* [libosmo-sigtran homepage](https://osmocom.org/projects/libosmo-sccp/wiki)
* [osmo-stp homepage](https://osmocom.org/projects/osmo-stp/wiki)

GIT Repository
--------------

You can clone from the official git repository using

	git clone https://gitea.osmocom.org/osmocom/libosmo-sigtran

There is a web interface at <https://gitea.osmocom.org/osmocom/libosmo-sigtran>

Documentation
-------------

osmo-stp User Manuals and VTY reference manuals are [optionally] built in PDF form
as part of the build process.

Pre-rendered PDF versions of the manuals can be found at:
https://ftp.osmocom.org/docs/osmo-stp/

Forum
-----

We welcome any libosmo-sigtran + osmo-stp related discussions in the
[Cellular Network Infrastructure -> 2G/3G Core Network](https://discourse.osmocom.org/c/cni/2g-3g-cn/)
section of the osmocom discourse (web based Forum).

Mailing List
------------

Discussions related to osmo-stp are happening on the
openbsc@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/openbsc for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Issue Tracker
-------------

We use the issue trackers of osmocom.org for tracking the state of bug reports and feature requests.  Feel free
to submit any issues you may find, or help us out by resolving existing issues.

* [libosmo-sigtran issue tracker](https://osmocom.org/projects/libosmo-sccp/issues)
* [osmo-stp issue tracker](https://osmocom.org/projects/osmo-stp/issues)

Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We use a Gerrit based patch submission/review process for managing contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for more details

The current patch queue can be seen at <https://gerrit.osmocom.org/#/q/project:libosmo-sccp+status:open>
