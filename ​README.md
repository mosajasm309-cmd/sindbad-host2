# ![PS4](https://img.shields.io/badge/-PS4-003791?style=flat&logo=PlayStation) SINDBAD HOST Linux Loader
(Southbridge: Aeolia & Belize(2) & Baikal)

**Linux Loader** kexec for PlayStation 4.

The host with precompiled Linux payloads works well with any integrated payload loader in a HEN. Just open the web browser and cache the host—it will also work offline too: [SINDBAD HOST](https://sindbad-host2.github.io/)

<img src="img.jpg" width="75%">

There's also a great [Linux setup guide by DionKill](https://dionkill.github.io/ps4-linux-tutorial/)


# Supported Firmwares

*   FW 5.05 ✅
*   FW 6.72 ✅
*   FW 7.00 / 7.01 / 7.02 ✅
*   FW 7.50 / 7.51 / 7.55 ✅ 
*   FW 8.00 / 8.01 / 8.03 ✅
*   FW 8.50 / 8.52 ✅
*   FW 9.00 ✅ 
*   FW 9.03 / 9.04 ✅ 
*   FW 9.50 / 9.51 / 9.60 ✅ 
*   FW 10.00 / 10.01 ✅ 
*   FW 10.50 / 10.70 / 10.71 ✅ 
*   FW 11.00 ✅ 
*   FW 11.02 ✅ 
*   FW 11.50 / 11.52 ✅
*   FW 12.00 / 12.02 ✅ 
*   FW 12.50 / 12.52 ✅
*   FW 13.00 ✅
*   FW 13.02 / FW 13.04 ✅
*   FW 13.50 ✅
*   FW 13.52 ✅
*   FW 14.00 ✅
*   FW 14.02 (?)

## Info 
The internal path by default is at: ``/data/linux/boot``, however it'll also check for ``/user/system/boot/`` in case it was not found.

the rest is coming from the initramfs.cpio.gz init configuration
so you can go into the rescue shell without a usb stick just upload the ``bzImage`` and ``initramfs.cpio.gz`` over ftp to your PS4 Drive:

``/data/linux/boot/[bzimage,initramfs.cpio.gz]`` 

or

``/user/system/boot/[bzimage,initramfs.cpio.gz]`` 

and of course it will work too with a USB / HDD Drive.  USB have highest priority. If a USB is connected, it will use the bzImage and initramfs.cpio.gz from there .

### vram.txt
Control VRAM size via a plain text file containing a number in **MB** (not GB).

| vram.txt value | VRAM allocated
|:-:|:-:|
| `32`  | 32 MB
| `64`  | 64 MB
| `128` | 128 MB
| `256` | 256 MB
| `512` | 512 MB
| `1024` | 1 GB
| `2048` | 2 GB
| `2560` | 2.5 GB
| `3072` | 3 GB
| `4096` | 4 GB

Default is 1024 MB (1 GB) if vram.txt is missing or invalid. Minimum is **32 MB**.

## Server Use (Low VRAM Payloads)

- **Why 32MB, 64MB, 128MB, 256MB, 512MB?** The idea behind these low VRAM payloads is for users who are repurposing the PS4 as a server for RAM and CPU intensive tasks. If you're just running server stuff headless, you don't need 1GB+ of memory wasted on the GPU. Using these payloads frees up that shared unified memory to be used as regular system RAM instead. 

- **How to use:** 
  - **Option 1:** Just run the payload with the desired VRAM size (e.g. `-32mb`, `-64mb`, etc.).
  - **Option 2:** Add the value (e.g. `32`, `64`, `128`, etc.) into your `vram.txt` file to set it manually. Don't use these if you plan on gaming or using heavy desktop graphics!
>
# ![PS4](https://img.shields.io/badge/-PS4-003791?style=flat&logo=PlayStation) SINDBAD HOST Linux Loader
(Southbridge: Aeolia & Belize(2) & Baikal)

**Linux Loader** kexec for PlayStation 4.

The host with precompiled Linux payloads works well with any integrated payload loader in a HEN. Just open the web browser and cache the host—it will also work offline too: [SINDBAD HOST](https://sindbad-host2.github.io/)

<img src="img.jpg" width="75%">

There's also a great [Linux setup guide by DionKill](https://dionkill.github.io/ps4-linux-tutorial/)


# Supported Firmwares

*   FW 5.05 ✅
*   FW 6.72 ✅
*   FW 7.00 / 7.01 / 7.02 ✅
*   FW 7.50 / 7.51 / 7.55 ✅ 
*   FW 8.00 / 8.01 / 8.03 ✅
*   FW 8.50 / 8.52 ✅
*   FW 9.00 ✅ 
*   FW 9.03 / 9.04 ✅ 
*   FW 9.50 / 9.51 / 9.60 ✅ 
*   FW 10.00 / 10.01 ✅ 
*   FW 10.50 / 10.70 / 10.71 ✅ 
*   FW 11.00 ✅ 
*   FW 11.02 ✅ 
*   FW 11.50 / 11.52 ✅
*   FW 12.00 / 12.02 ✅ 
*   FW 12.50 / 12.52 ✅
*   FW 13.00 ✅
*   FW 13.02 / FW 13.04 ✅
*   FW 13.50 ✅
*   FW 13.52 ✅
*   FW 14.00 ✅
*   FW 14.02 (?)

## Info 
The internal path by default is at: ``/data/linux/boot``, however it'll also check for ``/user/system/boot/`` in case it was not found.

the rest is coming from the initramfs.cpio.gz init configuration
so you can go into the rescue shell without a usb stick just upload the ``bzImage`` and ``initramfs.cpio.gz`` over ftp to your PS4 Drive:

``/data/linux/boot/[bzimage,initramfs.cpio.gz]`` 

or

``/user/system/boot/[bzimage,initramfs.cpio.gz]`` 

and of course it will work too with a USB / HDD Drive.  USB have highest priority. If a USB is connected, it will use the bzImage and initramfs.cpio.gz from there .

### vram.txt
Control VRAM size via a plain text file containing a number in **MB** (not GB).

| vram.txt value | VRAM allocated
|:-:|:-:|
| `32`  | 32 MB
| `64`  | 64 MB
| `128` | 128 MB
| `256` | 256 MB
| `512` | 512 MB
| `1024` | 1 GB
| `2048` | 2 GB
| `2560` | 2.5 GB
| `3072` | 3 GB
| `4096` | 4 GB

Default is 1024 MB (1 GB) if vram.txt is missing or invalid. Minimum is **32 MB**.

## Server Use (Low VRAM Payloads)

- **Why 32MB, 64MB, 128MB, 256MB, 512MB?** The idea behind these low VRAM payloads is for users who are repurposing the PS4 as a server for RAM and CPU intensive tasks. If you're just running server stuff headless, you don't need 1GB+ of memory wasted on the GPU. Using these payloads frees up that shared unified memory to be used as regular system RAM instead. 

- **How to use:** 
  - **Option 1:** Just run the payload with the desired VRAM size (e.g. `-32mb`, `-64mb`, etc.).
  - **Option 2:** Add the value (e.g. `32`, `64`, `128`, etc.) into your `vram.txt` file to set it manually. Don't use these if you plan on gaming or using heavy desktop graphics!
>
