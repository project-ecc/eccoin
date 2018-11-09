# Building Eccoin with Gitian

Note: These instructions were created on a machine that natively ran Ubuntu 16.04.5 (Xenial). No virtualization was used.

## Verify hardware compatability
Verify that your machine has the hardware virtualizations extensions to build

#### For intel the following command should give you a list of flags

`grep -e 'vmx' /proc/cpuinfo`

#### For amd the following command should give you a list of flags

`grep -e 'svm' /proc/cpuinfo`

If there is no output make sure that virtualization extensions is enabled in BIOS.
Verify that KVM modules are loaded in the kernel.
It should be loaded by default. Verify this using
`lsmod | grep kvm`. You should get some output.

Running `modprobe kvm` might also help

## Install dependencies

`apt-get install software-properties-common`

`add-apt-repository ppa:bitcoin/bitcoin`

`apt-get update`

```
apt-get install git ruby sudo apt-cacher-ng qemu-utils debootstrap lxc python-cheetah parted kpartx bridge-utils make curl build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils python3 libboost-all-dev libdb4.8-dev libdb4.8++-dev libminiupnpc-dev libzmq3-dev python-vm-builder apache2 apt-cacher-ng python-vm-builder qemu
```

git clone https://github.com/project-ecc/eccoin ~/eccoin

checkout the branch of eccoin you plan on building

git clone https://github.com/project-ecc/ecc-gitian-builder ~/ecc-gitian-builder

mkdir ~/ecc-releases
mkdir ~/gitian.sigs

## Setup Gitian and build

#### Setup Gitian descriptors

```
export SIGNER=(your Gitian key, ie bluematt, sipa, etc)
export VERSION=(version)
export TAG=(tag or commit hash you want to build)
export ECC_PATH=~/eccoin
export RELEASE_DIR=~/ecc-releases/${VERSION}
```

#### Make the base gitian image

Eccoin builds on an Ubuntu trusty VM, create that base vm image by doing the following:
```
cd ecc-gitian-builder
./bin/make-base-vm --arch amd64 --suite trusty
```

If you get an error code here it is due to an issue with python. To fix it find the file

`/usr/lib/python2.7/dist-packages/VMBuilder/plugins/ubuntu/dapper.py`

Find the line:
```
self.run_in_target('apt-get', '-y', '--force-yes', 'dist-upgrade',
```
and replace it with:
```
self.run_in_target('apt-get', '-y', '--force-yes', '--option=Dpkg::Options::=--force-confnew', 'dist-upgrade',
```

The full explaination of the fix can be found here: https://bugs.launchpad.net/vmbuilder/+bug/1659952

#### Perform the Build

The formula for making a build is
```
./bin/gbuild --url eccoin=${ECC_PATH} --commit eccoin=${TAG} ${ECC_PATH}/contrib/gitian-descriptors/(descriptor file)
```

For example if I wanted to build windows binaries:
```
./bin/gbuild --url eccoin=${ECC_PATH} --commit eccoin=${TAG} ${ECC_PATH}/contrib/gitian-descriptors/gitian-win.yml
```

#### Signing

Linux Signing

```
./bin/gsign --signer $SIGNER --release ${VERSION}-linux --destination ~/gitian.sigs/ ${ECC_PATH}/contrib/gitian-descriptors/gitian-linux.yml
```

Windows Signing

```
./bin/gsign --signer $SIGNER --release ${VERSION}-win-unsigned --destination ~/gitian.sigs/ ${ECC_PATH}/contrib/gitian-descriptors/gitian-win.yml
```

MacOS Signing

```
./bin/gsign --signer $SIGNER --release ${VERSION}-osx-unsigned --destination ~/gitian.sigs/ ${ECC_PATH}/contrib/gitian-descriptors/gitian-osx.yml
```
