/*
 * wifi-scan library implementation
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
 
#include "wifi_scan.h"

#include <libmnl/libmnl.h> //netlink libmnl
#include <linux/nl80211.h> //nl80211 netlink
#include <linux/genetlink.h> //generic netlink

#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <fcntl.h> //fntnl (set descriptor options)
#include <errno.h> //errno

// Internal data structures used throughout the library

struct netlink_channel
{
	struct mnl_socket *nl;
	char *buf;
	uint16_t nl80211_id;
	uint32_t ifindex;
	uint32_t sequence;
	void *context;
};

struct wifi_scan
{
	struct netlink_channel notification_channel;
	struct netlink_channel command_channel;
};


// DECLARATIONS AND TOP-DOWN LIBRARY OVERVIEW

// INITIALIZATION

struct context_CTRL_CMD_GETFAMILY
{
	uint32_t id_NL80211_MULTICAST_GROUP_SCAN;
};

struct wifi_scan *wifi_scan_init(const char *interface); 

void init_netlink_channel(struct netlink_channel *channel, const char *interface);
void init_netlink_socket(struct netlink_channel *channel);

void subscribe_NL80211_MULTICAST_GROUP_SCAN(struct netlink_channel *channel, uint32_t scan_group_id);

int get_family_and_scan_ids(struct netlink_channel *channel);
int handle_CTRL_CMD_GETFAMILY(const struct nlmsghdr *nlh, void *data);
void parse_CTRL_ATTR_MCAST_GROUPS(struct nlattr *nested, struct netlink_channel *channel);

// CLEANUP
void wifi_scan_close(struct wifi_scan *wifi);
void close_netlink_channel(struct netlink_channel *channel);

// SCANNING

int wifi_scan_all(struct wifi_scan *wifi, struct bss_info *bss_infos, int bss_infos_length);

// SCANNING - notification related

struct context_NL80211_MULTICAST_GROUP_SCAN
{
	int new_scan_results;
	int scan_triggered;
};

void read_past_notifications(struct netlink_channel *notifications);
void set_channel_non_blocking(struct netlink_channel *channel);
void set_channel_blocking(struct netlink_channel *channel);
int handle_NL80211_MULTICAST_GROUP_SCAN(const struct nlmsghdr *nlh, void *data);
int trigger_scan_if_necessary(struct netlink_channel *commands, struct context_NL80211_MULTICAST_GROUP_SCAN *scanning);
int trigger_scan(struct netlink_channel *channel);
void wait_for_new_scan_results(struct netlink_channel *notifications);

// SCANNING - scan related

struct context_NL80211_CMD_NEW_SCAN_RESULTS
{
	struct bss_info *bss_infos;
	int bss_infos_length;
	int scanned;	
};

int get_scan(struct netlink_channel *channel);
int handle_NL80211_CMD_NEW_SCAN_RESULTS(const struct nlmsghdr *nlh, void *data);
void parse_NL80211_ATTR_BSS(struct nlattr *nested, struct netlink_channel *channel);
void parse_NL80211_BSS_INFORMATION_ELEMENTS(struct nlattr *attr, char SSID_OUT[33]);
void parse_NL80211_BSS_BSSID(struct nlattr *attr, uint8_t bssid_out[BSSID_LENGTH]);

// STATION

struct context_NL80211_CMD_NEW_STATION
{
	struct station_info *station;
};

int wifi_scan_station(struct wifi_scan *wifi,struct station_info *station);
int get_station(struct netlink_channel *channel, uint8_t bssid[BSSID_LENGTH]);
int handle_NL80211_CMD_NEW_STATION(const struct nlmsghdr *nlh, void *data);
void parse_NL80211_ATTR_STA_INFO(struct nlattr *nested, struct netlink_channel *channel);

// NETLINK HELPERS

// NETLINK HELPERS - message construction/sending/receiving

struct nlmsghdr *prepare_nl_message(uint32_t type, uint16_t flags, uint8_t genl_cmd, struct netlink_channel *channel);
void send_nl_message(struct nlmsghdr *nlh, struct netlink_channel *channel);
int receive_nl_message(struct netlink_channel *channel, mnl_cb_t callback);

// NETLINK HELPERS - validation

struct attribute_validation
{
	int attr;
	int type;
	int len;
};

struct validation_data
{
	struct nlattr **attribute_table;
	int attribute_length;
	const struct attribute_validation *validation;
	int validation_length;	
};

int validate(const struct nlattr *attr, void *data);

// GENNERAL PURPOSE
void die(const char *s);
void die_errno(const char *s);

// #####################################################################
// IMPLEMENTATION


const struct attribute_validation NL80211_VALIDATION[]={
 {CTRL_ATTR_FAMILY_ID, MNL_TYPE_U16},
 {CTRL_ATTR_MCAST_GROUPS, MNL_TYPE_NESTED} };
 
const struct attribute_validation NL80211_MCAST_GROUPS_VALIDATION[]={
 {CTRL_ATTR_MCAST_GRP_ID, MNL_TYPE_U32},
 {CTRL_ATTR_MCAST_GRP_NAME, MNL_TYPE_STRING} };

const struct attribute_validation NL80211_BSS_VALIDATION[]={
 {NL80211_BSS_BSSID, MNL_TYPE_BINARY, 6},
 {NL80211_BSS_INFORMATION_ELEMENTS, MNL_TYPE_BINARY},
 {NL80211_BSS_STATUS, MNL_TYPE_U32},
 {NL80211_BSS_SIGNAL_MBM, MNL_TYPE_U32},
 {NL80211_BSS_SEEN_MS_AGO, MNL_TYPE_U32} };

const struct attribute_validation NL80211_NEW_SCAN_RESULTS_VALIDATION[]={
 {NL80211_ATTR_IFINDEX, MNL_TYPE_U32},
 {NL80211_ATTR_SCAN_SSIDS, MNL_TYPE_NESTED},
 {NL80211_ATTR_BSS, MNL_TYPE_NESTED} };
 
const struct attribute_validation NL80211_CMD_NEW_STATION_VALIDATION[]={
 {NL80211_ATTR_STA_INFO, MNL_TYPE_NESTED},
};

const struct attribute_validation NL80211_STA_INFO_VALIDATION[]={
 {NL80211_STA_INFO_SIGNAL, MNL_TYPE_U8},
 {NL80211_STA_INFO_RX_PACKETS, MNL_TYPE_U32},
 {NL80211_STA_INFO_TX_PACKETS, MNL_TYPE_U32}
};

const int NL80211_VALIDATION_LENGTH=sizeof(NL80211_VALIDATION)/sizeof(struct attribute_validation); 
const int NL80211_MCAST_GROUPS_VALIDATION_LENGTH=sizeof(NL80211_MCAST_GROUPS_VALIDATION)/sizeof(struct attribute_validation);
const int NL80211_BSS_VALIDATION_LENGTH=sizeof(NL80211_BSS_VALIDATION)/sizeof(struct attribute_validation);
const int NL80211_NEW_SCAN_RESULTS_VALIDATION_LENGTH=sizeof(NL80211_NEW_SCAN_RESULTS_VALIDATION)/sizeof(struct attribute_validation);
const int NL80211_CMD_NEW_STATION_VALIDATION_LENGTH=sizeof(NL80211_CMD_NEW_STATION_VALIDATION)/sizeof(struct attribute_validation);
const int NL80211_STA_INFO_VALIDATION_LENGTH=sizeof(NL80211_STA_INFO_VALIDATION)/sizeof(struct attribute_validation);

// INITIALIZATION

struct wifi_scan *wifi_scan_init(const char *interface)
{			
	struct wifi_scan *wifi=malloc(sizeof(struct wifi_scan));
	if(wifi==NULL)
		die("Insufficient memory - malloc(sizeof(struct wifi_data)");
	
	init_netlink_channel(&wifi->notification_channel, interface);
	
	struct context_CTRL_CMD_GETFAMILY family_context ={0};
	wifi->notification_channel.context=&family_context;

	if(get_family_and_scan_ids(&wifi->notification_channel) == -1)
		die_errno("GetFamilyAndScanId failed");
		
	if(family_context.id_NL80211_MULTICAST_GROUP_SCAN == 0)
		die("No scan multicast group in generic netlink nl80211\n");

	init_netlink_channel(&wifi->command_channel, interface);
	wifi->command_channel.nl80211_id = wifi->notification_channel.nl80211_id;
		
	subscribe_NL80211_MULTICAST_GROUP_SCAN(&wifi->notification_channel, family_context.id_NL80211_MULTICAST_GROUP_SCAN);	

	return wifi;
}

// prerequisities:
// - proper interface, e.g. wlan0, wlan1
void init_netlink_channel(struct netlink_channel *channel, const char *interface)
{
	channel->sequence=1;
	channel->buf=(char*) malloc(MNL_SOCKET_BUFFER_SIZE);		

	if(channel->buf == NULL)
		die("Insufficent memory for netlink socket buffer");

	channel->ifindex=if_nametoindex(interface); 
	
	if(channel->ifindex==0)
		die_errno("Incorrect network interface");
		
	channel->context=NULL;
	
	init_netlink_socket(channel);
}

void init_netlink_socket(struct netlink_channel *channel)
{
	channel->nl = mnl_socket_open(NETLINK_GENERIC);

	if (channel->nl == NULL)
		die_errno("mnl_socket_open");
		
	if (mnl_socket_bind(channel->nl, 0, MNL_SOCKET_AUTOPID) < 0)
		die_errno("mnl_socket_bind");	
}

// prerequisities:
// - channel initialized with init_netlink_channel
void subscribe_NL80211_MULTICAST_GROUP_SCAN(struct netlink_channel *channel, uint32_t scan_group_id)
{
	if (mnl_socket_setsockopt(channel->nl, NETLINK_ADD_MEMBERSHIP, &scan_group_id, sizeof(int)) < 0)
		die_errno("mnl_socket_set_sockopt");
}

// prerequisities:
// - channel initialized with init_netlink_channel
// - channel context of type context_CTRL_CMD_GETFAMILY
int get_family_and_scan_ids(struct netlink_channel *channel)
{	
	struct nlmsghdr *nlh=prepare_nl_message(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK,  CTRL_CMD_GETFAMILY, channel);
	mnl_attr_put_u32(nlh, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);	
	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, NL80211_GENL_NAME);

	send_nl_message(nlh, channel);

	return receive_nl_message(channel, handle_CTRL_CMD_GETFAMILY);
}

// prerequisities:
// - netlink_channel passed as data
// - data->context of type struct context_CTRL_CMD_GETFAMILY
int handle_CTRL_CMD_GETFAMILY(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[CTRL_ATTR_MAX+1] = {};
	struct genlmsghdr *genl = (struct genlmsghdr *)mnl_nlmsg_get_payload(nlh);
	struct netlink_channel *channel = (struct netlink_channel*)data;
	struct validation_data vd={tb, CTRL_ATTR_MAX, NL80211_VALIDATION, NL80211_VALIDATION_LENGTH};

	mnl_attr_parse(nlh, sizeof(*genl), validate, &vd);

	if (!tb[CTRL_ATTR_FAMILY_ID])
		die("No family id attribute");
		
	channel->nl80211_id=mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
				
	if (tb[CTRL_ATTR_MCAST_GROUPS])		
		parse_CTRL_ATTR_MCAST_GROUPS(tb[CTRL_ATTR_MCAST_GROUPS], channel);
	
	return MNL_CB_OK;
}

// prerequisities:
// - data->context of type struct context_CTRL_CMD_GETFAMILY
void parse_CTRL_ATTR_MCAST_GROUPS(struct nlattr *nested, struct netlink_channel *channel)
{
	struct nlattr *pos;

	mnl_attr_for_each_nested(pos, nested)
	{
		struct nlattr *tb[CTRL_ATTR_MCAST_GRP_MAX+1] = {};
		struct validation_data vd={tb, CTRL_ATTR_MCAST_GRP_MAX, NL80211_MCAST_GROUPS_VALIDATION, NL80211_MCAST_GROUPS_VALIDATION_LENGTH};

		mnl_attr_parse_nested(pos, validate, &vd);

		if ( tb[CTRL_ATTR_MCAST_GRP_NAME])
		{
			const char *name=mnl_attr_get_str(tb[CTRL_ATTR_MCAST_GRP_NAME]);
			
			if( strcmp(name, "scan") == 0 )
			{
				if (tb[CTRL_ATTR_MCAST_GRP_ID])
				{
					struct context_CTRL_CMD_GETFAMILY *context=channel->context;
					context->id_NL80211_MULTICAST_GROUP_SCAN= mnl_attr_get_u32(tb[CTRL_ATTR_MCAST_GRP_ID]);
				}
				else
					die("Missing id attribute for scan multicast group");
			}			
		}
	}
}


// CLEANUP

// prerequisities:
// - wifi initialized with wifi_scan_init
void wifi_scan_close(struct wifi_scan *wifi)
{
	close_netlink_channel(&wifi->notification_channel);
	close_netlink_channel(&wifi->command_channel);
	free(wifi);
}

// prerequisities:
// - channel initalized with init_netlink-channel
void close_netlink_channel(struct netlink_channel *channel)
{
	free(channel->buf);
	mnl_socket_close(channel->nl);
}


// SCANNING

//handle also trigger abort

// prerequisities:
// - wifi initialized with wifi_scan_init
// - bss_info table of sized bss_info_length passed 
int wifi_scan_all(struct wifi_scan *wifi, struct bss_info *bss_infos, int bss_infos_length)
{
	struct netlink_channel *notifications=&wifi->notification_channel;
	struct context_NL80211_MULTICAST_GROUP_SCAN scanning={0,0};
	notifications->context=&scanning;

	struct netlink_channel *commands=&wifi->command_channel;
	struct context_NL80211_CMD_NEW_SCAN_RESULTS scan_results = {bss_infos, bss_infos_length, 0};
	commands->context=&scan_results;
	
	//somebody else might have triggered scanning or even the results can be already waiting 
	read_past_notifications(notifications);
	
	//if no results yet or scan not triggered then trigger it.
	//the device can be busy - we have to take it into account
	if( trigger_scan_if_necessary(commands, &scanning) == -1)
		return -1; //most likely with errno set to EBUSY
	
	//now just wait for trigger/new_scan_results
	wait_for_new_scan_results(notifications);
	
	//finally read the scan
	get_scan(commands);
	
	return scan_results.scanned;
}

// SCANNING - notification related

// prerequisities
// - subscribed to scan group with subscribe_NL80211_MULTICAST_GROUP_SCAN
// - context_NL80211_MULTICAST_GROUP_SCAN set for notifications
void read_past_notifications(struct netlink_channel *notifications)
{
	set_channel_non_blocking(notifications);
	int ret, run_ret;

	while( (ret = mnl_socket_recvfrom(notifications->nl, notifications->buf, MNL_SOCKET_BUFFER_SIZE) ) >= 0)
	{
		//the line below fills context about past scans/triggers 
		run_ret = mnl_cb_run(notifications->buf, ret, 0, 0, handle_NL80211_MULTICAST_GROUP_SCAN, notifications);
		if(run_ret <= 0)
			die_errno("ReadPastNotificationsNonBlocking mnl_cb_run failed");		
	}
		
	if(ret == -1)
		if( !(errno == EINPROGRESS || errno == EWOULDBLOCK) ) 
			die_errno("ReadPastNotificationsNonBlocking mnl_socket_recv failed");
	//no more notifications waiting
	set_channel_blocking(notifications);
}

// prerequisities
// - channel initialized with init_netlink_channel
void set_channel_non_blocking(struct netlink_channel *channel)
{
	int fd = mnl_socket_get_fd(channel->nl);
	int flags = fcntl(fd, F_GETFL, 0);
	if(flags == -1)
		die_errno("SetChannelNonBlocking F_GETFL");
	if( fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		die_errno("SetChannelNonBlocking F_SETFL");
}

// prerequisities
// - channel initialized with init_netlink_channel
void set_channel_blocking(struct netlink_channel *channel)
{
	int fd = mnl_socket_get_fd(channel->nl);
	int flags = fcntl(fd, F_GETFL, 0);
	if(flags == -1)
		die_errno("SetChannelNonBlocking F_GETFL");
	if( fcntl(fd, F_SETFL, flags &  ~O_NONBLOCK) == -1)
		die_errno("SetChannelNonBlocking F_SETFL");	
}

// prerequisities:
// - subscribed to scan group with subscribe_NL80211_MULTICAST_GROUP_SCAN
// - netlink_channel passed as data
// - data->context of type struct context_NL80211_MULTICAST_GROUP_SCAN
int handle_NL80211_MULTICAST_GROUP_SCAN(const struct nlmsghdr *nlh, void *data)
{
	struct netlink_channel *channel=data;	
	struct context_NL80211_MULTICAST_GROUP_SCAN *context = channel->context;	
	
	struct genlmsghdr *genl = (struct genlmsghdr *)mnl_nlmsg_get_payload(nlh);
	
//	printf("Got message type %d seq %d pid  %d genl cmd %d \n", nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid, genl->cmd);
	if(genl->cmd == NL80211_CMD_TRIGGER_SCAN)
	{
		context->scan_triggered=1;
//		printf("TRIGGER type %u seq %u pid  %u genl cmd %u\n", nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid, genl->cmd);
		return MNL_CB_OK; //do nothing for now			
	}
	else if(genl->cmd == NL80211_CMD_NEW_SCAN_RESULTS)
	{
//		printf("NEW SCAN RESULTS type %u seq %u pid  %u genl cmd %u\n", nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid, genl->cmd);
		if(nlh->nlmsg_pid==0 &&  nlh->nlmsg_seq==0)
			context->new_scan_results = 1;
		return MNL_CB_OK; //do nothing for now			
	}
	else
	{
		fprintf(stderr, "Ignoring generic netlink command type %u seq %u pid  %u genl cmd %u\n",nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid, genl->cmd);
		return MNL_CB_OK;
	}
}


// prerequisities:
// - commands initialized with init_netlink_channel
// - scanning updated with read_past_notifications
int trigger_scan_if_necessary(struct netlink_channel *commands, struct context_NL80211_MULTICAST_GROUP_SCAN *scanning)
{
	if(!scanning->new_scan_results && !scanning->scan_triggered)
		if(trigger_scan(commands) == -1)
			return -1; //most likely errno set to EBUSY which means hardware is doing something else, try again later
	return 0;
}

// prerequisities:
// - channel initialized with init_netlink_channel
int trigger_scan(struct netlink_channel *channel)
{
	struct nlmsghdr *nlh=prepare_nl_message(channel->nl80211_id, NLM_F_REQUEST  | NLM_F_ACK, NL80211_CMD_TRIGGER_SCAN, channel);	
	mnl_attr_put_u32(nlh,  NL80211_ATTR_IFINDEX, channel->ifindex); 
	send_nl_message(nlh, channel);	
	return receive_nl_message(channel, handle_NL80211_CMD_NEW_SCAN_RESULTS);
}

// prerequisities
// - channel initalized with init_netlink_channel
// - subscribed to scan group with subscribe_NL80211_MULTICAST_GROUP_SCAN
// - context_NL80211_MULTICAST_GROUP_SCAN set for notifications
void wait_for_new_scan_results(struct netlink_channel *notifications)
{
	struct context_NL80211_MULTICAST_GROUP_SCAN *scanning=notifications->context;
	int ret;
	
	while(!scanning->new_scan_results)
	{
		if ( (ret = mnl_socket_recvfrom(notifications->nl, notifications->buf, MNL_SOCKET_BUFFER_SIZE)) <=0 )
			die_errno("Waiting for new scan results failed - mnl_socket_recvfrom");
			
		if ( (ret=mnl_cb_run(notifications->buf, ret, 0, 0, handle_NL80211_MULTICAST_GROUP_SCAN, notifications)) <=0 )
			die_errno("Processing notificatoins failed - mnl_cb_run");
	}
}

// SCANNING - scan related

// prerequisities:
// - channel initalized with init_netlink_channel
// - channel context of type context_NL80211_CMD_NEW_SCAN_RESULTS
int get_scan(struct netlink_channel *channel)
{
	struct nlmsghdr *nlh=prepare_nl_message(channel->nl80211_id, NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK, NL80211_CMD_GET_SCAN, channel);	
	mnl_attr_put_u32(nlh,  NL80211_ATTR_IFINDEX, channel->ifindex); 

	send_nl_message(nlh, channel);	
	return receive_nl_message(channel, handle_NL80211_CMD_NEW_SCAN_RESULTS);			
}

// prerequisities:
// - netlink_channel passed as data
// - data->context of type context_NL80211_CMD_NEW_SCAN_RESULTS
int handle_NL80211_CMD_NEW_SCAN_RESULTS(const struct nlmsghdr *nlh, void *data)
{
	struct netlink_channel *channel=data;	
	struct nlattr *tb[NL80211_ATTR_MAX+1] = {};
	struct validation_data vd={tb, NL80211_ATTR_MAX, NL80211_NEW_SCAN_RESULTS_VALIDATION, NL80211_NEW_SCAN_RESULTS_VALIDATION_LENGTH};
	struct genlmsghdr *genl = (struct genlmsghdr *)mnl_nlmsg_get_payload(nlh);
	
//	printf("NSR type %u seq %u pid  %u genl cmd %u\n", nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid, genl->cmd);
	
	if(genl->cmd != NL80211_CMD_NEW_SCAN_RESULTS)
	{
		fprintf(stderr, "Ignoring generic netlink command %u seq %u pid  %u genl cmd %u\n", nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid, genl->cmd);
		return MNL_CB_OK;	
	}
	
	//seq 0 - notification from kernel, then pid should also 0, if it is result of our scan we have sequence and our pid
//	int new_scan_results= nlh->nlmsg_seq != 0 && nlh->nlmsg_pid != 0;
		
	mnl_attr_parse(nlh, sizeof(*genl), validate, &vd);
	
	if(tb[NL80211_ATTR_IFINDEX])
	{
	//	uint32_t ifindex=mnl_attr_get_u32(tb[NL80211_ATTR_IFINDEX]);
//		printf("ifindex %u\n", ifindex);
	}
	if (!tb[NL80211_ATTR_BSS])
		return MNL_CB_OK;
	
	parse_NL80211_ATTR_BSS(tb[NL80211_ATTR_BSS], channel);
				
	return MNL_CB_OK;
}

// prerequisities:
// - channel context of type context_NL80211_CMD_NEW_SCAN_RESULTS
void parse_NL80211_ATTR_BSS(struct nlattr *nested, struct netlink_channel *channel)
{
	struct nlattr *tb[NL80211_BSS_MAX+1] = {};
	struct validation_data vd={tb, NL80211_BSS_MAX, NL80211_BSS_VALIDATION, NL80211_BSS_VALIDATION_LENGTH};
	struct context_NL80211_CMD_NEW_SCAN_RESULTS *scan_results = channel->context;
	struct bss_info *bss = scan_results->bss_infos + scan_results->scanned;

	mnl_attr_parse_nested(nested, validate, &vd); 

	enum nl80211_bss_status status=BSS_NONE;
	
	if(tb[NL80211_BSS_STATUS])
		status=mnl_attr_get_u32(tb[NL80211_BSS_STATUS]);

	//if we have found associated station store first as last and associated as first
	if(status==NL80211_BSS_STATUS_ASSOCIATED || status==NL80211_BSS_STATUS_ASSOCIATED || status==NL80211_BSS_STATUS_IBSS_JOINED)
	{
		if(scan_results->scanned>0 && scan_results->scanned < scan_results->bss_infos_length)
			memcpy(bss, scan_results->bss_infos, sizeof(struct bss_info));
		bss=scan_results->bss_infos;
	}

	//check bounds, make exception if we have found associated station and replace previous data
	if( scan_results->scanned >= scan_results->bss_infos_length || (scan_results->bss_infos_length==0 && bss==scan_results->bss_infos) )
	{
		++scan_results->scanned;
		return;
	}

	if ( tb[NL80211_BSS_BSSID])
		parse_NL80211_BSS_BSSID(tb[NL80211_BSS_BSSID], bss->bssid);
			
	if ( tb[NL80211_BSS_INFORMATION_ELEMENTS])
		parse_NL80211_BSS_INFORMATION_ELEMENTS(tb[NL80211_BSS_INFORMATION_ELEMENTS], bss->ssid);

	if ( tb[NL80211_BSS_SIGNAL_MBM])
		bss->signal_mbm=mnl_attr_get_u32(tb[NL80211_BSS_SIGNAL_MBM]);

	if ( tb[NL80211_BSS_SEEN_MS_AGO])
		bss->seen_ms_ago = mnl_attr_get_u32(tb[NL80211_BSS_SEEN_MS_AGO]);

	bss->status=status;

	++scan_results->scanned;
}

//This is guesswork! Read up on that!!! I don't think it's netlink in this attribute, some lower beacon layer
void parse_NL80211_BSS_INFORMATION_ELEMENTS(struct nlattr *attr, char SSID_OUT[33])
{
	const char *payload=mnl_attr_get_payload(attr);
	int len=mnl_attr_get_payload_len(attr);
	if(len==0 || payload[0]!=0 || payload[1] > 32 || payload[1] > len-2)
	{
		fprintf(stderr, "SSID len 0 or payload not starting from 0 or payload length > 32 or payload length > length-2\n!");
		SSID_OUT="\0";
		return;
	}
	int ssid_len=payload[1];
	strncpy(SSID_OUT, payload+2, ssid_len);
	SSID_OUT[ssid_len]='\0';
}
void parse_NL80211_BSS_BSSID(struct nlattr *attr, uint8_t bssid_out[BSSID_LENGTH])
{
	const char *payload=mnl_attr_get_payload(attr);
	int len=mnl_attr_get_payload_len(attr);
	
	if(len != BSSID_LENGTH)
	{
		fprintf(stderr, "BSSID length != %d, ignoring", BSSID_LENGTH);
		memset(bssid_out, 0, BSSID_LENGTH);
		return;	
	}

	memcpy(bssid_out, payload, BSSID_LENGTH);
}

// STATION

// prerequisities:
// - wifi initialized with wifi_scan_init
int wifi_scan_station(struct wifi_scan *wifi,struct station_info *station)
{
	struct netlink_channel *commands=&wifi->command_channel;
	struct bss_info bss;

	struct context_NL80211_CMD_NEW_SCAN_RESULTS scan_results = {&bss, 1, 0};
	commands->context=&scan_results;
	get_scan(commands);

	if(scan_results.scanned==0)
		return 0;

	struct context_NL80211_CMD_NEW_STATION station_results = {station};
	commands->context=&station_results;
	get_station(commands, bss.bssid);
	
	memcpy(station->bssid, bss.bssid, BSSID_LENGTH);
	memcpy(station->ssid, bss.ssid, SSID_MAX_LENGTH_WITH_NULL);
	station->status=bss.status;
		
	return 1;
}

// prerequisites: 
// - channel initalized with init_netlink_channel
// - context_NL80211_CMD_NEW_STATION set for channel
int get_station(struct netlink_channel *channel, uint8_t bssid[BSSID_LENGTH])
{
	struct nlmsghdr *nlh=prepare_nl_message(channel->nl80211_id, NLM_F_REQUEST | NLM_F_ACK, NL80211_CMD_GET_STATION, channel);	
	mnl_attr_put_u32(nlh,  NL80211_ATTR_IFINDEX, channel->ifindex); 
	mnl_attr_put(nlh,  NL80211_ATTR_MAC, BSSID_LENGTH, bssid); 
	send_nl_message(nlh, channel);	
	return receive_nl_message(channel, handle_NL80211_CMD_NEW_STATION);			
}

// prerequisities:
// - netlink_channel passed as data
// - data->context of type context_NL80211_CMD_NEW_STATION
int handle_NL80211_CMD_NEW_STATION(const struct nlmsghdr *nlh, void *data)
{
	struct netlink_channel *channel=data;	
	struct nlattr *tb[NL80211_ATTR_MAX+1] = {};
	struct validation_data vd={tb, NL80211_ATTR_MAX, NL80211_CMD_NEW_STATION_VALIDATION, NL80211_CMD_NEW_STATION_VALIDATION_LENGTH};
	struct genlmsghdr *genl = (struct genlmsghdr *)mnl_nlmsg_get_payload(nlh);
		
	if(genl->cmd != NL80211_CMD_NEW_STATION)
	{
		fprintf(stderr, "Ignoring generic netlink command %u seq %u pid  %u genl cmd %u\n", nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_pid, genl->cmd);
		return MNL_CB_OK;	
	}
	
	mnl_attr_parse(nlh, sizeof(*genl), validate, &vd);

	if(!tb[NL80211_ATTR_STA_INFO]) //or error, no statoin
		return MNL_CB_OK;
		
	parse_NL80211_ATTR_STA_INFO(tb[NL80211_ATTR_STA_INFO], channel);		
		
	return MNL_CB_OK;
	
}

// prerequisities:
// - channel context of type context_NL80211_CMD_NEW_STATION
void parse_NL80211_ATTR_STA_INFO(struct nlattr *nested, struct netlink_channel *channel)
{
	struct nlattr *tb[NL80211_STA_INFO_MAX+1] = {};
	struct validation_data vd={tb, NL80211_STA_INFO_MAX, NL80211_STA_INFO_VALIDATION, NL80211_STA_INFO_VALIDATION_LENGTH};
	struct context_NL80211_CMD_NEW_STATION *station_results = channel->context;
	struct station_info *station= station_results->station;
		
	mnl_attr_parse_nested(nested, validate, &vd);

	if ( tb[NL80211_STA_INFO_SIGNAL])
		station->signal_dbm=(int8_t)mnl_attr_get_u8(tb[NL80211_STA_INFO_SIGNAL]);
	if (tb[NL80211_STA_INFO_RX_PACKETS])
		station->rx_packets=mnl_attr_get_u32(tb[NL80211_STA_INFO_RX_PACKETS]);
	if (tb[NL80211_STA_INFO_TX_PACKETS])
		station->tx_packets=mnl_attr_get_u32(tb[NL80211_STA_INFO_TX_PACKETS]);
}


// NETLINK HELPERS

// NETLINK HELPERS - message construction/sending/receiving

// prerequisities:
// - channel initialized with init_netlink_channel
struct nlmsghdr *prepare_nl_message(uint32_t type, uint16_t flags, uint8_t genl_cmd, struct netlink_channel *channel)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	
	nlh = mnl_nlmsg_put_header(channel->buf);
	nlh->nlmsg_type	= type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = channel->sequence;

	genl = (struct genlmsghdr*)mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = genl_cmd;
	genl->version = 1;
	return nlh;
}

// prerequisities:
// - prepare_nl_message called first
// - mnl_attr_put_xxx used if additional attributes needed	
void send_nl_message(struct nlmsghdr *nlh, struct netlink_channel *channel)
{
	if (mnl_socket_sendto(channel->nl, nlh, nlh->nlmsg_len) < 0)
		die_errno("mnl_socket_sendto");	
}

// prerequisities:
// - send_nl_message called first
// - prerequisities for callback matched	
int receive_nl_message(struct netlink_channel *channel, mnl_cb_t callback)
{
	int ret;
	unsigned int portid = mnl_socket_get_portid(channel->nl);
	
	ret = mnl_socket_recvfrom(channel->nl, channel->buf, MNL_SOCKET_BUFFER_SIZE);
		
	while (ret > 0)
	{
		ret = mnl_cb_run(channel->buf, ret, channel->sequence, portid, callback, channel);
		if (ret <= 0)			
			break;
		ret = mnl_socket_recvfrom(channel->nl, channel->buf, MNL_SOCKET_BUFFER_SIZE);
	}

	++channel->sequence;

	return ret;
}

// NETLINK HELPERS - validation

// prerequisities:
// - data of type validation_data
int validate(const struct nlattr *attr, void *data)
{
	struct validation_data *vd=data;
	const struct nlattr **tb = (const struct nlattr**) vd->attribute_table;
	int type = mnl_attr_get_type(attr) ,i;
	
//	printf("%d\n", type);
	
	if (mnl_attr_type_valid(attr, vd->attribute_length) < 0)
		return MNL_CB_OK;

	for(i=0; i < vd->validation_length;++i)
		if(type == vd->validation[i].attr)
		{
			int len=vd->validation[i].len;
			if(len==0 && mnl_attr_validate(attr, vd->validation[i].type) < 0)
			{
					perror("mnl_attr_validate error");
					return MNL_CB_ERROR;
			}
			if(len != 0 && mnl_attr_validate2(attr, vd->validation[i].type, len) < 0)
			{
				perror("mnl_attr_validate error");
				return MNL_CB_ERROR;
			}
		}
		
	tb[type] = attr;
	return MNL_CB_OK;			
}

// GENNERAL PURPOSE

void die(const char *s)
{
	fprintf(stderr, s);
	fprintf(stderr, "\n");
	exit(1);
}

void die_errno(const char *s)
{
    perror(s);
    exit(1);
}
