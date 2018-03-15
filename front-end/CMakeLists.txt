cmake_minimum_required(VERSION 2.8.7)

project(front-end)

include(ExternalProject)

if(${CRETE_TARGET_VD} STREQUAL "E1000")
  set(QEMU_VD_FLAG "CRETE_VD_E1000")
elseif(${CRETE_TARGET_VD} STREQUAL "EEPRO100")
  set(QEMU_VD_FLAG "CRETE_VD_EEPRO100")
elseif(${CRETE_TARGET_VD} STREQUAL "NE2000")
  set(QEMU_VD_FLAG "CRETE_VD_NE2000")
elseif(${CRETE_TARGET_VD} STREQUAL "PCNET")
  set(QEMU_VD_FLAG "CRETE_VD_PCNET")
elseif(${CRETE_TARGET_VD} STREQUAL "RTL8139")
  set(QEMU_VD_FLAG "CRETE_VD_RTL8139")
else()
  message (FATAL_ERROR "CRETE_TARGET_VD is not set corrected: only 'E1000', 'EEPRO100', 'NE2000', 'PCNET', and 'RTL8139' supported")
endif()

ExternalProject_Add(
	qemu-2.3

	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/qemu-2.3
	BUILD_IN_SOURCE 1

        DOWNLOAD_COMMAND ""
	UPDATE_COMMAND ""

	CONFIGURE_COMMAND
        ./configure
        --enable-tcg-interpreter
        --target-list=i386-softmmu,x86_64-softmmu
        "--extra-cflags=-I${CMAKE_SOURCE_DIR}/lib/include -I${CMAKE_BINARY_DIR}/lib/boost/boost-prefix/src/boost_1_59_0 -D${QEMU_VD_FLAG}"
        "--extra-ldflags=-L${CMAKE_BINARY_DIR}/bin -L${CMAKE_BINARY_DIR}/bin/boost"

	BUILD_COMMAND make -j7

	INSTALL_COMMAND
        ln -sf ${CMAKE_CURRENT_SOURCE_DIR}/qemu-2.3/i386-softmmu/crete-qemu-2.3-system-i386 ${CMAKE_BINARY_DIR}/bin/crete-qemu-2.3-system-i386 &&
        ln -sf ${CMAKE_CURRENT_SOURCE_DIR}/qemu-2.3/x86_64-softmmu/crete-qemu-2.3-system-x86_64 ${CMAKE_BINARY_DIR}/bin/crete-qemu-2.3-system-x86_64
	)

add_dependencies(qemu-2.3 crete_test_case boost)

add_custom_target(qemu-2.3-remake ALL
  COMMAND  make -j7
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/qemu-2.3
  DEPENDS qemu-2.3)
