cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME dns_relay)
project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 17)

include_directories(./include/)

include_directories(./third_part/easylogger/)
include_directories(./third_part/easylogger/inc/)

set(EASYLOGGER_SRC
        ./third_part/easylogger/src/elog.c
        ./third_part/easylogger/src/elog_async.c
        ./third_part/easylogger/src/elog_utils.c
        ./third_part/easylogger/src/elog_buf.c
        ./third_part/easylogger/port/elog_port.c
        )

add_executable(${PROJECT_NAME}
        ${EASYLOGGER_SRC}
        src/main.cpp
        src/dns_package.cpp
        include/dns_package.h
        src/dns_db.cpp
        include/dns_db.h
        src/dns_helper.cpp
        include/dns_helper.h
        include/main.h
        src/dns_proxy.cpp
        include/dns_proxy.h)

target_link_libraries(${PROJECT_NAME} uv pthread)