# 2020 MITRE Collegiate eCTF Code (Texas A&M University)

This repository contains our secure DRM system for MITRE's 2020 [Embedded System CTF](http://mitrecyberacademy.org/competitions/embedded/). 

## Getting Started
Please see the [Getting Started Guide](getting_started.md).

## Project structure
The example code is structured as follows

 * `boot-image/` - Contains a stock FSBL, `image.ub`, and `u-boot.elf` for booting the project on the board. The stock FSBL is only provided for the purposes of making the `miPod.bin`, since `bootgen` requires you provide a bootloader when creating a `.bin` image.
 * `mb/` - Contains example DRM project for running on the soft-core MicroBlaze. See [DRM README](mb/README.md)
 * `miPod/` - Contains example miPod project for running the Linux-side miPod driver. See [miPod README](miPod/README.md)
 * `pl/` - Contains example PL implementation with soft-core MicroBlaze and audio codec. See [PL README](pl/README.md)
 * `tools/` - Contains example provisioning tools. See [tools README](tools/README.md)
 * `vagrant/` - Contains files for configuring the Vagrant environment. See [Vagrant README](vagrant/README.md)
 * `vivado-boards/` - Contains Vivado libraries for the board
 * `Vagrantfile` - Vagrantfile for launching the Vagrant environment - DO NOT CHANGE
 * `sample-audio` - Sample audio files for you to use

## DRM File Format
```
***Graphic not to scale

   start
   ____________________________
   | WAV file format metadata   |
   | (44 bytes)                 |
   |____________________________|
                 V
   ------------------------------
   | Song metadata keyed Blake3 |
   | Hash                       | ---> use 32-bit
   | (32 bytes)                 |      metadata key
   |____________________________|
   | Speck CBC Initialization   |
   | Vector                     |
   | (16 bytes)                 |
   |____________________________|
   | int - num of encrypted     |
   | audio chunks               |
   | (4 bytes)                  |
   |____________________________|
   | int - encrypted audio len  |
   | (4 bytes)                  |
   |____________________________|
   | DRM Song metadata          |
   | (100 bytes)                | ---> struct drm_md
   |____________________________|
                 V
   ------------------------------
   | encrypted [audio+padding]  |
   | (max of 32 Megabytes       | ---> use 32-bit key
   |  = 2098 16000B chunks      |      Speck 128/256
   |____________________________|
                 V
   ------------------------------ ___
   | Encrypted Audio Chunk #0   |    |
   | + IV keyed Blake3 hash     |    |
   | (32 bytes)                 |    |
   |____________________________|    |
   |            ...             |    |--> max of 2098 hashes
   |____________________________|    |    = 64 KB total,
   | Encrypted Audio Chunk #n   |    |    use 32-bit chunk
   | + IV keyed Blake3 hash     |    |    key
   | (32 bytes)                 |    |
   |____________________________| ___|
   end

MAX DRM FILE SIZE = 
   32 MB song --> (44+32+16+4+4+100+33,554,432+(2098*32)) = 33621768
``` 

## Security Features

* In order to protect audio confidentiality, our system encrypts songs using the lightweight block cipher Speck (https://github.com/nsacyber/simon-speck). We use CBC mode with 128-bit block size and 256-bit key size.

* For song integrity/authenticity, we use the fast cryptographic hash Blake3 (https://github.com/BLAKE3-team/BLAKE3). We use 128-bit keys to create keyed hashes.

* When a song is loaded to play in the DRM, we first verify the integrity and authenticity of the song by computing a keyed Blake3 hash over the DRM metadata. If this check passes, we can decrypt and play the song. To decrypt, we take a 16KB chunk of audio at one time and verify its integrity/authenticity using a keyed Blake3 hash over the encrypted chunk + the initialization vector. If this passes, we decrypt the chunk and pass it to the audio codec.

* To store and verify user pins, we create a Blake3 hash of a user's pin+username.

## Optional Features

We have implemented the following optional features:
* fast-forward/rewind audio
* support high quality audio at 48KHz.

