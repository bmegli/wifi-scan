WIFI_SCAN = wifi_scan.o
EXAMPLES = wifi-scan-station wifi-scan-all
CC = gcc
CXX = g++
DEBUG = 
CFLAGS = -O2 -Wall -c $(DEBUG)
CXX_FLAGS = -O2 -std=c++11 -Wall -c $(DEBUG)
LFLAGS = -O2 -Wall -lmnl $(DEBUG)
	
all : $(WIFI_SCAN) $(EXAMPLES)
	
wifi_scan.o : wifi_scan.h wifi_scan.c
	$(CC) $(CFLAGS) wifi_scan.c

examples: $(EXAMPLES)
			
wifi-scan-station : wifi_scan.o wifi_scan_station.o
	$(CC) $(LFLAGS) wifi_scan.o wifi_scan_station.o -o wifi-scan-station

wifi-scan-all : wifi_scan.o wifi_scan_all.o
	$(CC) $(LFLAGS) wifi_scan.o wifi_scan_all.o -o wifi-scan-all
		
wifi_scan_station.o : wifi_scan.h examples/wifi_scan_station.c
	$(CC) $(CFLAGS) examples/wifi_scan_station.c

wifi_scan_all.o : wifi_scan.h examples/wifi_scan_all.c
	$(CC) $(CFLAGS) examples/wifi_scan_all.c
		
clean:
	\rm -f *.o examples/*.o $(WIFI_SCAN) $(EXAMPLES)
