# Building WolfSSL for Xilinx Microblaze

***YOU DO NOT NEED TO READ THIS UNLESS YOU WANT TO REBUILD WOLFSSL. WOLFSSL HAS ALREADY BEEN BUILT AND PROVIDED IN BRANCH WOLFSSL.***

This document is specifically for cross-compiling WolfSSL for the Xilinx Microblaze soft processor core within the vagrant development environment. For details on setting up the environment, see the [Vagrant README](../vagrant/README.md).

## Dependencies

WolfSSL is easily built using GNU *autoconf* and *make*.
```shell
sudo apt install autoconf
```
*make* should already be available on the virtual machine.

You also need to have the Xilinx Microblaze toolchain installed and on your path (`mb-gcc`, `mb-ar`, etc.). If you don't have them, follow all of the provision instructions in the [Vagrant README](../vagrant/README.md#Provision-Instructions).

## Get WolfSSL

Download WolfSSL version 4.3.0. You can do so through their website (https://www.wolfssl.com/download/).

*Note: you do not need to fill out your personal information, simply select your download and agree to the licensing agreement.*

## For Reference During Build

Before you begin building, https://www.wolfssl.com/docs/wolfssl-manual/ch2/ will be important in getting more detailed information about building and porting WolfSSL. For example, sections 2.4.3 (Removing Features), 2.4.4 (Enabling Features Disabled by Default), and 2.4.5 (Customizing or Porting wolfSSL) were heavily used to create this document.

## Build

We will be cross-compiling WolfSSL for usage on the Xilinx Microblaze soft processor core.

1. Unzip the WolfSSL zip archive and navigate into the folder (we will call the WolfSSL home directory `{wolfssl-home}`).
2. Add the following lines to `{wolfssl-home/wolfssl/wolfcrypt/settings.h}`:
```c
#define NO_WOLFSSL_DIR
#define SINGLE_THREADED
#define LITTLE_ENDIAN_ORDER
```
3. Run *configure*, disabling unwanted features and enabling wanted features. Notice we are creating a WolfCrypt-only build. (, see 2.3.4 at https://www.wolfssl.com/docs/wolfssl-manual/ch2/)
```shell
./configure --host microblaze-xilinx-elf --enable-cryptonly --enable-pkcs7--enable-harden --disable-aesgcm --disable-sha512 --disable-sha384 --disable-eccshamir --disable-ecc --disable-dh --disable-md5 --disable-sha --disable-sha224 --disable-sha3 --disable-poly1305 --disable-chacha --disable-filesystem --disable-hashdrbg --disable-examples --disable-crypttests --disable-pkcs12 --disable-rng CFLAGS="-mlittle-endian"
```

4. If *configure* finished successfully without errors, run
```bash
make
```
If you only want to build the static library and not the additional items (examples, testsuite, benchmark app, etc.), run
```bash
make src/libwolfssl.la
```
5. Your newly compiled library will be available in `{wolfssl-home}/src/.libs/`. For our purposes, there is no need to install the library on the system.

## Using WolfSSL in the Insecure Example Design

This section is **NOT IMPORTANT** unless you are rebuilding WolfSSL, as these steps have already been done on branch **wolfssl (now merged to master)** in **carlislemc/tamu-ectf-2020**.

If you have found the need to further customize the build for WolfSSL, and have already performed the steps above, follow these steps to use in the example project.

1. Copy the library to the lib directory in the DRM board support package.
```bash
cp {wolfssl-home}/src/.libs/wolflibwolfssl.a /etcf/mb/drm_audio_fw/microblaze_0/lib/
```
2. Copy the WolfSSL headers to the include directory in the DRM board support package.
```bash
cp -r {wolfssl-home}/wolfssl /etcf/mb/drm_audio_fw/microblaze_0/include/
```
3. Modify the build process to pass `-lwolfssl` to the linker when building project `drm_audio_fw`. *TODO(andrew): how to do this through command line?*

   1. Launch Xilinx sdk with `xsdk`.
   2. Set the workspace directory to `/ectf/mb`.
   3. Import the `Cora-Z7-07S`, `drm_audio_fw`, `drm_audio_fw_bsp`, and `miPod` projects into the SDK.
   4. From Project Explorer, right-click the `drm_audio_fw` project and click `Properties`.
   5. In the Properties window for this project, expand `C/C++ Build` and click the subsection `Settings`.
   6. In the next menu, expand `MicroBlaze gcc linker` and click on the subheading `Libraries`. There should be two text boxes on the right side of the window. We want to add a new library into the box labeled `Libraries (-l)`.
   7. Click the `Add` icon and type in wolfssl for the library name. Click Ok and Ok once more.
   8. You should be able to build the project and use WolfSSL cryptographic utilities.
