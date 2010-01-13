Introduction
============

HPCFS (**H**TTP **P**roxy **C**ache **F**ile**s**ystem) is a FUSE module aimed at mounting one or several HTTP URLs as a filesystem. Such mounted filesystem will benefits from the following features:

* **Caching**: First request on a file will be cached on the local filesystem and subsequent requests will use the cached version
* **Merging**: Can join several URLs contents together to form a virtually unique content by using the Dailymotion's HTTP-WhoHas technique

NOTE: This module isn't a complete FUSE filesystem implementation. For instance, only direct file accesses will work, directory listing, file editing, permissions etc. are not implemented.

Configuration
=============

The HPCFS module relies on a single configuration file (referenced through the -o hpcfsconfig=**configuration file path** CLI option). This configuration file is typically located in /etc/hpcfs.conf but multiple configuration files may be used (and referenced) in case multiple HPCFS mount-points are used on the same server.

Once the configuration file has been edited to match the production environment (see directives and typical configuration below), the module is run using the following command:

``
/usr/sbin/hpcfs **mountpoint** -o hpcfsconfig=/etc/hpcfs.conf
``

Where **mountpoint** is an existing folder where the remote files are made available (on-demand/on-access) to the requesting softwares.

The list of available configuration directives is presented below:

### `HostMap <name> <list>`

This directive defines a table of back-end storage clusters (under the name **name**), each back-end containing at most 32 "nodes". It may be used up to 32 times in the configuration file. Back-ends are space-separated inside the list, and nodes are comma-separated inside a back-end. The special $[**start**-**end**] variable may be used (at most once per node definition) to synthesize values between **start** and **end**.
The hostmaps may be referenced in the Rewrite directives with the special ${**name**} variable.


### `Rewrite <local> <remote>`

This directive defines the mapping between a local file path (in the locally mounted filesystem) and the corresponding remote content URL (on the back-end storage clusters, no default value).
It may be used up to 32 times in the configuration file. The captured portions within the **local** parameter may be back-referenced in the **remote** parameter with the $**n** syntax (where **n** is a positive integer).
The special ${**name**} variable references the **name** host-map for potential HTTP WhoHas lookup in the **remote** parameter (see "HostMap" above).


### `ConnectTimeout <timeout>`

This directive defines the maximum time spent establishing a network connection (in seconds, default is 5 seconds).


### `MapTimeout <timeout>`

This directive defines the maximum time spent localizing a given content on the back-end storage clusters (a.k.a. "HTTP WhoHas", in seconds, default is 5 seconds).
ReceiveTimeout **timeout**
This directive defines the maximum time spent receiving data from the back-end storage clusters (in seconds, default is 30 seconds).


### `MaxDepth <depth>`

This directive defines the maximum count while following redirects (3xx HTTP codes or errors, default is 8).


### `CacheRoot <path>`

This directive specifies the root folder for cached files (no default value, mandatory).


### `Log <path>`

This directive specifies the activity logfile path (mainly used by proxy-cleaner, no default value).
The path may contain strftime expressions to automate log rotation for instance (the parent folders are created as needed).

The log format is as follow:
``
YYYY-MM-DD HH:MM:SS|CACHE-IN|<cached file path>
YYYY-MM-DD HH:MM:SS|CACHE-OUT|<cached file path>
``