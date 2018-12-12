cmake_minimum_required(VERSION 3.9)

project(
    wifi-scan 
    DESCRIPTION "This is a small C/C++ library for monitoring signal strength of WiFi networks. It can collect data from associated station only or all networks around"
)

add_library(wifi-scan SHARED wifi_scan.c)
target_link_libraries(wifi-scan mnl)
install(TARGETS wifi-scan DESTINATION lib)
install(FILES wifi_scan.h DESTINATION include)

add_executable(wifi-scan-all examples/wifi_scan_all.c)
target_link_libraries(wifi-scan-all wifi-scan)

add_executable(wifi-scan-station examples/wifi_scan_station.c)
target_link_libraries(wifi-scan-station wifi-scan)
