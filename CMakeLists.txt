#cmake_minimum_required(VERSION 3.5.2) - this one is required to find boost libs >= 1.64, but we have to use old one for centos/rhel
cmake_minimum_required(VERSION 2.8)

project(qore-process-module)

# internal copy of boost was prepared as seen in 3rd_party README file
option(USE_INTERNAL_BOOST "Enforce using internal copy of boost libraries" OFF)

set (VERSION_MAJOR 1)
set (VERSION_MINOR 0)
set (VERSION_PATCH 5)

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake )

find_package(Qore 1.0 REQUIRED)
#find_package(Threads REQUIRED)
if (NOT USE_INTERNAL_BOOST)
    find_package(Boost 1.71 COMPONENTS filesystem system)
endif (NOT USE_INTERNAL_BOOST)

if (Boost_FOUND)
    message(STATUS "Boost libs found: ${Boost_INCLUDE_DIRS} : ${Boost_LIBRARIES}")
else (Boost_FOUND)
    message(WARNING "Boost NOT found - using internal copy of boost libs")
    set(BOOST_INTERNAL 1)
endif (Boost_FOUND)

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

include(CheckCXXSymbolExists)
check_cxx_symbol_exists(kill signal.h HAVE_KILL)

set(CPP_SRC
    src/processpriv.cpp
)

if (BOOST_INTERNAL)
    set (CPP_SRC ${CPP_SRC}
            3rd_party/libs/system/src/error_code.cpp
            3rd_party/libs/filesystem/src/codecvt_error_category.cpp
            3rd_party/libs/filesystem/src/operations.cpp
            3rd_party/libs/filesystem/src/path.cpp
            3rd_party/libs/filesystem/src/path_traits.cpp
            3rd_party/libs/filesystem/src/portability.cpp
            3rd_party/libs/filesystem/src/unique_path.cpp
            3rd_party/libs/filesystem/src/utf8_codecvt_facet.cpp
            3rd_party/libs/filesystem/src/windows_file_codecvt.cpp
            3rd_party/libs/filesystem/src/windows_file_codecvt.hpp
        )
    include_directories( 3rd_party )
else (BOOST_INTERNAL)
    include_directories( ${Boost_INCLUDE_DIRS} )
endif (BOOST_INTERNAL)

set(QPP_SRC
    src/process.qpp
    src/QC_Process.qpp
)

include_directories( ${CMAKE_SOURCE_DIR}/src )

if (WIN32)
    add_definitions(-DWINDOWS_API)
    set(WIN_LIBS wsock32 ws2_32)
endif (WIN32)

qore_wrap_qpp_value(QPP_SOURCES ${QPP_SRC})

SET (module_name "process")

add_library(${module_name} MODULE ${CPP_SRC} ${QPP_SOURCES})

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(${module_name} proc)
endif()

configure_file(${CMAKE_SOURCE_DIR}/cmake/unix-config.h.cmake
${CMAKE_BINARY_DIR}/unix-config.h)

if (DEFINED ENV{DOXYGEN_EXECUTABLE})
    set(DOXYGEN_EXECUTABLE $ENV{DOXYGEN_EXECUTABLE})
endif()

qore_external_binary_module(${module_name} "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}" ${Boost_LIBRARIES} ${WIN_LIBS})

qore_dist("${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

qore_config_info()

if (DOXYGEN_FOUND)
  qore_wrap_dox(QORE_DOX_SRC ${QORE_DOX_TMPL_SRC})
  add_custom_target(QORE_MOD_DOX_FILES DEPENDS ${QORE_DOX_SRC})
  add_dependencies(docs-module QORE_MOD_DOX_FILES)
endif()
