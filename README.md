# wifi-scan

This is a small C/C++ library for monitoring signal strength of WiFi networks. It can collect data from:

- associated station only (rapidly)
- all networks around (slow passive scan)

## Platforms 

Any platforms supporting nl80211 netlink interface (new 802.11 interface).
Generally *nix platforms.

## Hardware

Wireless devices that have cfg80211/mac80211 driver.
Currently all new Linux wireless drivers should be written targeting either cfg80211 for fullmac devices or mac80211 for softmac devices.

## State

The return values of public library functions are subject to change (mainly error codes).
Currently if anything goes wrong library dies cleanly with error message on stderr explaining what happened.
Note that if library dies - *it also kills your program* and you have no chance to recover.

## Dependencies

The library depends on [libmnl](http://www.netfilter.org/projects/libmnl/) for netlink nl80211 user space - kernel space communication.

## Building Instructions

``` bash
# update package repositories
sudo apt-get update 
# get compilers and make
sudo apt-get install build-essential
# get dependencies
sudo apt-get install libmnl0 libmnl-dev
# get git
sudo apt-get install git
# clone the repository
git clone https://github.com/bmegli/wifi-scan.git

# finally build the library and examples
cd wifi-scan
make all
```

## Testing

Check your wireless interface name with `ifconfig`:
``` bash
ifconfig
```

Run `wifi-scan-station` with your interface, e.g. `wlan0`

``` bash
./wifi-scan-station wlan0
```

Run `wifi-scan-all` with your interface, e.g. `wlan0`.

Triggering a scan needs permission so:

``` bash
sudo ./wifi-scan-all wlan0
```

## Using

See examples directory for more complete and commented examples with error handling.

Normally you would call `wifi_scan_station` or `wifi_scan_all` in a loop.

### wifi-scan-station

``` C
	struct station_info station;
	struct wifi_scan *wifi = wifi_scan_init("wlan0");
	
	if (wifi_scan_station(wifi, &station) > 0 )
		printf("%s signal %d dBm avg %d dBm rx %u tx %u\n",
		station.signal_dbm, station.signal_avg_dbm,
		station.rx_packets, station.tx_packets);
	
	wifi_scan_close(wifi);
```

### wifi-scan-all

``` C 
	int status, i;
	struct bss_info bss[10]; 
	struct wifi_scan *wifi = wifi_scan_init("wlan0");

	status=wifi_scan_all(wifi, bss, 10);
		
	for(i=0;i<status && i<10;++i)	
		printf("%s signal %d dBm on %u MHz seen %d ms ago status %s\n",
		bss[i].signal_mbm/100, bss[i].frequency, bss[i].seen_ms_ago,
		(bss[i].status==BSS_ASSOCIATED ? "associated" : ""));

	wifi_scan_close(wifi);
```

### Compiling your code

Don't forget to link with `lmnl`

C
``` bash
gcc wifi_scan.c your_program.c -lmnl -o your-program
```

C++
``` bash
gcc -c wifi_scan.c
g++ -c your_program.cpp
g++ wifi_scan.o your_program.o -lmnl -o your-program
```

## Understanding nl80211 Netlink

Here are some of the resources that helped writing this library:

- Netlink Library (libnl) [documentation](https://www.infradead.org/~tgr/libnl/doc/core.html)
- Minimalistic Netlink Library (libmnl) doxygen [documentation](https://www.netfilter.org/projects/libmnl/doxygen/) and [code](https://git.netfilter.org/libmnl/)
- nl80211 [header file](http://lxr.free-electrons.com/source/include/uapi/linux/nl80211.h)
- iw [code](http://git.kernel.org/?p=linux/kernel/git/jberg/iw.git)
- wavemon [code](https://github.com/uoaerg/wavemon)
- wpa_supplicant and hostapd [code](http://ftp.tku.edu.tw/NetBSD/NetBSD-current/src/external/bsd/wpa/dist/src/drivers/driver_nl80211_scan.c)

And finally the implementation `wifi-scan.c` has some comments that may be usefull to you.

## License

Library is licensed under Mozilla Public License, v. 2.0

This is similiar to LGPL but more permissive:
- you can use it as LGPL in prioprietrary software
- unlike LGPL you may compile it statically with your code

Like in LGPL, if you modify this library, you have to make your changes available.
Making a github fork of the library with your changes satisfies those requirements perfectly.

## Additional information

### Building with CMake

Alternatively build examples and shared library with Cmake

``` bash
sudo apt-get install cmake
cd wifi-scan
mkdir build
cd build
cmake ..
make
```

