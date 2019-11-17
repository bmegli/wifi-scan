/*
 * wifi-scan library header
 *
 * Copyright 2016-2018 (C) Bartosz Meglicki <meglickib@gmail.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// some constants - mac address length, mac adress string length, max length of wireless network id with null character
enum wifi_constants {BSSID_LENGTH=6, BSSID_STRING_LENGTH=18, SSID_MAX_LENGTH_WITH_NULL=33};
// anything >=0 should mean that your are associated with the station
enum bss_status{BSS_NONE=-1, BSS_AUTHENTHICATED=0, BSS_ASSOCIATED=1, BSS_IBSS_JOINED=2};

// internal data used by the functions
struct wifi_scan;

// a single wireless network can have multiple BSSes working as network under one SSID
struct bss_info
{
	uint8_t bssid[BSSID_LENGTH]; //this is hardware mac address of your AP
	uint32_t frequency; // this is AP frequency in mHz
	char ssid[SSID_MAX_LENGTH_WITH_NULL]; //this is the name of your AP as you see it when connecting
	enum bss_status status;  //anything >=0 means that your are connected to this station/network
	int32_t signal_mbm;  //signal strength in mBm, divide it by 100 to get signal in dBm
	int32_t seen_ms_ago; //when the above information was collected
};

// like above
struct station_info
{
	uint8_t bssid[BSSID_LENGTH]; //this is hardware mac address of your AP
	char ssid[SSID_MAX_LENGTH_WITH_NULL]; //this is the name of your AP as you see it when connecting
	enum bss_status status;  //anything >=0 means that your are connected to this station/network
	int8_t signal_dbm;  //signal strength in dBm from last received PPDU
	int8_t signal_avg_dbm; //signal strength average in dBm
	uint32_t rx_packets; //the number of received packets
	uint32_t tx_packets; //the number of transmitted packets
};

/* Initializes the library
 *
 * If this functions fails the library will die with error message explaining why
 *
 * parameters:
 * interface - wireless interface, e.g. wlan0, wlan1
 *
 * returns:
 * struct wifi_scan * - pass it to all the functions in the library
 *
 */
struct wifi_scan *wifi_scan_init(const char *interface);

/* Frees the resources used by library
 *
 * parameters:
 * wifi - library data initialized with wifi_scan_init
 *
 * preconditions:
 * wifi initialized with wifi_scan_init
 */
void wifi_scan_close(struct wifi_scan *wifi);

/* Retrieve information about station you are associated to
 *
 * Retrieves information only about single station.
 * This function can be called repeateadly fast.
 *
 * parameters:
 * wifi - library data initialized with wifi_scan_init
 * station - to be filled with information
 *
 * returns:
 * -1 on error (errno is set), 0 if not associated to any station, 1 if data was retrieved
 *
 * preconditions:
 * wifi initialized with wifi_scan_init
 *
 */
int wifi_scan_station(struct wifi_scan *wifi, struct station_info *station);

/* Make a passive scan of all networks around.
 *
 * This function triggers passive scan if necessery, waits for completion and returns the data.
 * If some other scan was triggered in the meanwhile the library will collect it's results.
 * Triggering a scan requires permissions, for testing you may use sudo.
 *
 * Scanning may take some time (it can be order of second).
 * While scanning the link may be unusable for other programs!
 *
 * parameters:
 * wifi - library data initialized with wifi_scan_init
 * bss_infos - array of bss_info of size bss_infos_length
 * bss_infos_length - the length of passed array
 *
 * returns:
 * -1 on error (errno is set) or the number of found BSSes, the number may be greater then bss_infos_length
 *
 * Some devices may fail with -1 and errno=EBUSY if triggering scan when another scan is in progress. You may wait and retry in that case 
 *
 * preconditions:
 * wifi initialized with wifi_scan_init
 *
 */
int wifi_scan_all(struct wifi_scan *wifi, struct bss_info *bss_infos, int bss_infos_length);

#ifdef __cplusplus
}
#endif
