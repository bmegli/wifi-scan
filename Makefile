WIFI_SCAN = wifi-scan.o
EXAMPLES = /examples/wifi-scan-station /examples/wifi-scan-all
CC = gcc
CXX = g++
DEBUG = 
CFLAGS = -O2 -Wall -c $(DEBUG)
CXX_FLAGS = -O2 -std=c++11 -Wall -c $(DEBUG)
LFLAGS = -O2 -Wall -lmnl $(DEBUG)
	
wifi-scan.o : wifi_scan.h wifi_scan.c
	$(CC) $(C_FLAGS) wifi_scan.c

examples: $(EXAMPLES)
	
all : $(WIFI_SCAN) $(EXAMPLES)
		
examples/wifi-scan-station : wifi_scan.o examples/wifi_scan_station.o
	$(CC) $(L_FLAGS) wifi_scan.o examples/wifi_scan_station.o -o examples/wifi-scan-station

examples/wifi-scan-all : wifi_scan.o examples/wifi_scan_all.o
	$(CC) $(L_FLAGS) wifi_scan.o examples/wifi_scan_all.o -o examples/wifi-scan-all
		
examples/wifi_scan_station.o : wifi_scan.h examples/wifi_scan_station.c
	$(CC) $(C_FLAGS) examples/wifi_scan_station.c

examples/wifi_scan_all.o : wifi_scan.h examples/wifi_scan_all.c
	$(CC) $(C_FLAGS) examples/wifi_scan_all.c
		
clean:
	\rm -f *.o examples/*.o $(WIFI_SCAN) $(EXAMPLES)
