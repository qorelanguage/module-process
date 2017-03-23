cmake_minimum_required(VERSION 3.7.2)

project(qore-process-module)

# internal copy of boost was prepared by:
# tar xjf boost_1_63_0.tar.bz2
# cd boost_1_63_0/
# ./bootstrap.sh
# ./b2 tools/bcp
# ./dist/bin/bcp filesystem ~/src/qore/module-process/3rd_party
option(USE_INTERNAL_BOOST "Enforce using internal copy of boost libraries" OFF)

set (VERSION_MAJOR 0)
set (VERSION_MINOR 0)
set (VERSION_PATCH 1)

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake )


find_package(Qore REQUIRED)
#find_package(Threads REQUIRED)
if (NOT USE_INTERNAL_BOOST)
    find_package(Boost 1.63 COMPONENTS filesystem system)
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

set(CPP_SRC
    src/qoreprocesshandler.h
    src/processpriv.h
    src/processpriv.cpp
    src/boost/process/async_pipe.hpp
    src/boost/process/child.hpp
    src/boost/process/args.hpp
    src/boost/process/pipe.hpp
    src/boost/process/environment.hpp
    src/boost/process/env.hpp
    src/boost/process/start_dir.hpp
    src/boost/process/detail/throw_on_error.hpp
    src/boost/process/detail/traits.hpp
    src/boost/process/detail/handler.hpp
    src/boost/process/detail/posix/null_in.hpp
    src/boost/process/detail/posix/file_descriptor.hpp
    src/boost/process/detail/posix/pipe_in.hpp
    src/boost/process/detail/posix/close_in.hpp
    src/boost/process/detail/posix/wait_group.hpp
    src/boost/process/detail/posix/async_pipe.hpp
    src/boost/process/detail/posix/basic_pipe.hpp
    src/boost/process/detail/posix/file_in.hpp
    src/boost/process/detail/posix/asio_fwd.hpp
    src/boost/process/detail/posix/child_handle.hpp
    src/boost/process/detail/posix/pipe_out.hpp
    src/boost/process/detail/posix/group_ref.hpp
    src/boost/process/detail/posix/environment.hpp
    src/boost/process/detail/posix/compare_handles.hpp
    src/boost/process/detail/posix/handler.hpp
    src/boost/process/detail/posix/start_dir.hpp
    src/boost/process/detail/posix/cmd.hpp
    src/boost/process/detail/posix/is_running.hpp
    src/boost/process/detail/posix/on_exit.hpp
    src/boost/process/detail/posix/wait_for_exit.hpp
    src/boost/process/detail/posix/terminate.hpp
    src/boost/process/detail/posix/env_init.hpp
    src/boost/process/detail/posix/executor.hpp
    src/boost/process/detail/posix/async_handler.hpp
    src/boost/process/detail/posix/exe.hpp
    src/boost/process/detail/posix/async_in.hpp
    src/boost/process/detail/posix/close_out.hpp
    src/boost/process/detail/posix/null_out.hpp
    src/boost/process/detail/posix/async_out.hpp
    src/boost/process/detail/posix/search_path.hpp
    src/boost/process/detail/posix/basic_cmd.hpp
    src/boost/process/detail/posix/shell_path.hpp
    src/boost/process/detail/posix/use_vfork.hpp
    src/boost/process/detail/posix/signal.hpp
    src/boost/process/detail/posix/io_service_ref.hpp
    src/boost/process/detail/posix/fd.hpp
    src/boost/process/detail/posix/file_out.hpp
    src/boost/process/detail/posix/group_handle.hpp
    src/boost/process/detail/on_exit.hpp
    src/boost/process/detail/execute_impl.hpp
    src/boost/process/detail/async_handler.hpp
    src/boost/process/detail/windows/null_in.hpp
    src/boost/process/detail/windows/file_descriptor.hpp
    src/boost/process/detail/windows/pipe_in.hpp
    src/boost/process/detail/windows/close_in.hpp
    src/boost/process/detail/windows/wait_group.hpp
    src/boost/process/detail/windows/async_pipe.hpp
    src/boost/process/detail/windows/basic_pipe.hpp
    src/boost/process/detail/windows/file_in.hpp
    src/boost/process/detail/windows/job_workaround.hpp
    src/boost/process/detail/windows/asio_fwd.hpp
    src/boost/process/detail/windows/child_handle.hpp
    src/boost/process/detail/windows/pipe_out.hpp
    src/boost/process/detail/windows/group_ref.hpp
    src/boost/process/detail/windows/environment.hpp
    src/boost/process/detail/windows/compare_handles.hpp
    src/boost/process/detail/windows/handler.hpp
    src/boost/process/detail/windows/start_dir.hpp
    src/boost/process/detail/windows/cmd.hpp
    src/boost/process/detail/windows/is_running.hpp
    src/boost/process/detail/windows/locale.hpp
    src/boost/process/detail/windows/on_exit.hpp
    src/boost/process/detail/windows/wait_for_exit.hpp
    src/boost/process/detail/windows/terminate.hpp
    src/boost/process/detail/windows/env_init.hpp
    src/boost/process/detail/windows/executor.hpp
    src/boost/process/detail/windows/async_handler.hpp
    src/boost/process/detail/windows/async_in.hpp
    src/boost/process/detail/windows/close_out.hpp
    src/boost/process/detail/windows/null_out.hpp
    src/boost/process/detail/windows/show_window.hpp
    src/boost/process/detail/windows/async_out.hpp
    src/boost/process/detail/windows/search_path.hpp
    src/boost/process/detail/windows/basic_cmd.hpp
    src/boost/process/detail/windows/shell_path.hpp
    src/boost/process/detail/windows/io_service_ref.hpp
    src/boost/process/detail/windows/file_out.hpp
    src/boost/process/detail/windows/group_handle.hpp
    src/boost/process/detail/handler_base.hpp
    src/boost/process/detail/config.hpp
    src/boost/process/detail/traits/decl.hpp
    src/boost/process/detail/traits/env.hpp
    src/boost/process/detail/traits/wchar_t.hpp
    src/boost/process/detail/traits/async.hpp
    src/boost/process/detail/traits/error.hpp
    src/boost/process/detail/traits/group.hpp
    src/boost/process/detail/traits/cmd_or_exe.hpp
    src/boost/process/detail/basic_cmd.hpp
    src/boost/process/detail/child_decl.hpp
    src/boost/process/cmd.hpp
    src/boost/process/system.hpp
    src/boost/process/locale.hpp
    src/boost/process/windows.hpp
    src/boost/process/spawn.hpp
    src/boost/process/exe.hpp
    src/boost/process/async.hpp
    src/boost/process/search_path.hpp
    src/boost/process/error.hpp
    src/boost/process/async_system.hpp
    src/boost/process/shell.hpp
    src/boost/process/group.hpp
    src/boost/process/io.hpp
    src/boost/process/extend.hpp
    src/boost/process/posix.hpp
    src/boost/process/exception.hpp
    src/boost/process.hpp
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

qore_wrap_qpp_value(QPP_SOURCES ${QPP_SRC})

SET (module_name "process")

add_library(${module_name} SHARED ${CPP_SRC} ${QPP_SOURCES})

qore_binary_module(${module_name} "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}" ${Boost_LIBRARIES})

qore_dist("${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

qore_config_info()
