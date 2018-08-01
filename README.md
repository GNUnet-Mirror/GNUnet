<center><a href="https://gnunet.org"><img src="contrib/branding/logo/gnunet-logo-dark-text.svg" alt="GNUnet"width="300px"/></a></center>

> GNUnet is a *new* network protocol stack for building secure, distributed, and privacy-preserving applications. 

* [Install](#how-to-install-gnunet)
  * [From Source](#from-source)
  * [Using Docker](#docker)
* [Using GNUnet](#using-gnunet)
* [License](#license)

How to Install GNUnet
---------------------

### 1. From Source

**Dependencies**

Install these packages. Some of them may need to be installed from source depending on your OS.

```
- libmicrohttpd      >= 0.9.42
- libgcrypt          >= 1.6
- libgnurl           >= 7.35.0      (recommended, available from https://gnunet.org/gnurl)
- libcurl            >= 7.35.0      (alternative to libgnurl)
- libunistring       >= 0.9.2
- gnutls             >= 3.2.12      (highly recommended: a gnutls linked against libunbound)
- libidn             >= 1.0
- libextractor       >= 0.6.1       (highly recommended)
- openssl            >= 1.0         (binary, used to generate X.509 certificate)
- libltdl            >= 2.2         (part of GNU libtool)
- sqlite             >= 3.8         (default database, required)
- mysql              >= 5.1         (alternative to sqlite)
- postgres           >= 9.5         (alternative to sqlite)
- Texinfo            >= 5.2         [*1]
- which                             (for the bootstrap script)
- gettext
- zlib
- pkg-config
```


You can also install the dependencies with the [GNU Guix package manager:](https://https://www.gnu.org/software/guix/) by using the provided environment file: 

```shell
guix package -l guix-env.scm
```


**Using GNU Make**

```shell
./bootstrap # Run this to generate the configure files.
./configure # See the various flags avalable to you.
make
make install
```

**Using the [GNU Guix package manager:](https://https://www.gnu.org/software/guix/) **

```shell
# To build, run tests, and install:
guix package -f guix-env.scm

# To skip the testing phase:
guix package -f guix-env.scm:notest
```


### 2. Docker

```
cd docker
docker build -t gnunet .
```



## Using GNUnet

There are many possible ways to use the subsystems of GNUnet,	 we will provide a few examples in this section.


<center> <a href="contrib/gnunet-arch-full.svg"><img src="contrib/gnunet-arch-full.svg" alt="GNUnet Modular Architecture" width="400px" border="1px"/></a></center>

>***GNUnet is composed of over 30 modular subsystems***



### GNS

*coming soon*

### Cadet

#### Examples

Open a Cadet connection:

```shell
# Node 1
cadet -o <shared secret>
```

Conect to peer:

```shell
# Node 2
cadet <peer-id of Node 1> <shared secret>
```

#### Sharing Files

With the cli tool, you can also share files:

```shell
# Node 1
cadet -o <shared secret> > filename
```

```shell
# Node 2
cadet <peer-id of Node 1> <shared secret>
```


VPN
---

Running a Hostlist Server
--------------------------

GNUnet Configuration
--------------------------
### Examples

```yaml
[transport]
OPTIONS = -L DEBUG
PLUGINS = tcp
#PLUGINS = udp

[transport-tcp]
OPTIONS = -L DEBUG
BINDTO = 192.168.0.2
```

TODO: *explain what this does and add more*


Philosophy
-------------------------


Related Projects
-------------------------



 <a href="https://pep.foundation"><img src="https://pep.foundation/static/media/uploads/peplogo.svg" alt="pep.foundation" width="50px"/></a>  <a href="https://secushare.org"><img src="https://secushare.org/img/secushare-0444.png" alt="Secushare" width="50px"/></a>

 
