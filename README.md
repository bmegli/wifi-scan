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

The library depends on [libmnl](http://www.netfilter.org/projects/libmnl/) for netlink nl80211 user space - kernel communication.

## Building Instructions

### Compilers and make

``` bash
$ sudo apt-get update
$ sudo apt-get install build-essential 
```

### Dependencies

``` bash
$ sudo apt-get install libmnl0 libmnl-dev
```

### Getting git

``` bash
sudo apt-get install git
```

### Cloning the repository

``` bash
git clone https://github.com/bmegli/wifi-scan.git
```

### Building the examples

``` bash
gcc wifi_scan.c examples/wifi_scan_station.c -lmnl -o wifi-scan-station
```

``` bash
gcc wifi_scan.c examples/wifi_scan_all.c -lmnl -o wifi-scan-all
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
		printf("%s signal %d dBm %d rx %d tx\n",
		station.ssid,  station.signal_dbm,
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
		printf("%s signal %d dBm seen %d ms ago status %s\n",
		bss[i].ssid,  bss[i].signal_mbm/100, bss[i].seen_ms_ago,
		(bss[i].status==BSS_ASSOCIATED ? "associated" : ""));

	wifi_scan_close(wifi);

	return 0;
```