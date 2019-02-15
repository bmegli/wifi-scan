/*
 * wifi-scan-all example for wifi-scan library
 *
 * Copyright (C) 2016 Bartosz Meglicki <meglickib@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 *  This example makes passive scan of all the networks on interface.
 *  Passive scanning may take a while and your link may be unusable for other programs during the scan.
 *  For the above reason you should not call it too often (e.g. once a second) unless you don't mind side effects.
 * 
 *  Triggering a scan needs persmission. The program will fail with operation not supported error message if you don't have them.
 *  You can use sudo for testing.
 * 
 *  Program expects wireless interface as argument, e.g:
 *  wifi-scan-all wlan0
 * 
 */
 
#include "../wifi_scan.h"
#include <stdio.h>  //printf
#include <unistd.h> //sleep

//convert bssid to printable hardware mac address
const char *bssid_to_string(const uint8_t bssid[BSSID_LENGTH], char bssid_string[BSSID_STRING_LENGTH])
{
	snprintf(bssid_string, BSSID_STRING_LENGTH, "%02x:%02x:%02x:%02x:%02x:%02x",
         bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
	return bssid_string;
}

const int BSS_INFOS=10; //the maximum amounts of APs (Access Points) we want to store

void Usage(char **argv);

int main(int argc, char **argv)
{
	struct wifi_scan *wifi=NULL;    //this stores all the library information
	struct bss_info bss[BSS_INFOS]; //this is where we are going to keep informatoin about APs (Access Points)
	char mac[BSSID_STRING_LENGTH];  //a placeholder where we convert BSSID to printable hardware mac address
	int status, i;

	if(argc != 2)
	{
		Usage(argv);
		return 0;
	}

	printf("This is just example, this is library - not utility!\n\n");

	printf("Triggering scan needs permissions.\n");
	printf("The program will fail if you don't have them with message:\n");
	printf("\"Operation not permitted\". The simplest way is to use sudo. \n\n");

	printf("### Close the program with ctrl+c when you're done ###\n\n");
	
	// initialize the library with network interface argv[1] (e.g. wlan0)
	wifi=wifi_scan_init(argv[1]);

	while(1)
	{
		status=wifi_scan_all(wifi, bss, BSS_INFOS);
		
		//it may happen that device is unreachable (e.g. the device works in such way that it doesn't respond while scanning)
		//you may test for errno==EBUSY here and make a retry after a while, this is how my hardware works for example
		if(status<0)
			perror("Unable to get scan data");
		else //wifi_scan_all returns the number of found stations, it may be greater than BSS_INFOS that's why we test for both in the loop
			for(i=0;i<status && i<BSS_INFOS;++i)	
				printf("%s %s signal %d dBm on frequency %u MHz seen %d ms ago status %s\n",
				   bssid_to_string(bss[i].bssid, mac), 
				   bss[i].ssid,  
				   bss[i].signal_mbm/100, 
				   bss[i].frequency,
				   bss[i].seen_ms_ago, 
				   (bss[i].status==BSS_ASSOCIATED ? "associated" : "")
				);

		printf("\n");

		sleep(2);
	}
	
	//free the library resources
	wifi_scan_close(wifi);

	return 0;
}

void Usage(char **argv)
{
	printf("Usage:\n");
	printf("%s wireless_interface\n\n", argv[0]);
	printf("examples:\n");
	printf("%s wlan0\n", argv[0]);
	
}
