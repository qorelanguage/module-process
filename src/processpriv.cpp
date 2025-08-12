/*
    Qore Programming Language process Module

    Copyright (C) 2003 - 2025 Qore Technologies, s.r.o.

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
*/

#include "processpriv.h"

#include <unistd.h>

// std
#include <exception>
#include <cctype>
#include <stdexcept>

// boost
#include <boost/numeric/conversion/cast.hpp>

// module
#include "unix-config.h"

DLLLOCAL extern const TypedHashDecl* hashdeclMemorySummaryInfo;

static int page_size = sysconf(_SC_PAGESIZE);

// default I/O buffer size
static constexpr unsigned process_buf_size = 4096;

struct callback_initializer {
    ResolvedCallReferenceNode* f_on_success;
    ResolvedCallReferenceNode* f_on_setup;
    ResolvedCallReferenceNode* f_on_error;
    ResolvedCallReferenceNode* f_on_fork_error;
    ResolvedCallReferenceNode* f_on_exec_setup;
    ResolvedCallReferenceNode* f_on_exec_error;
    ExceptionSink* xsink;

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void on_success(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line)) {
        call("on_success", launcher, executable, f_on_success);
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL bp::error_code on_setup(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line)) {
        call("on_setup", launcher, executable, f_on_setup);
        return bp::error_code();
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void on_error(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line), const bp::error_code& ec) {
        call("on_error", launcher, executable, f_on_error, ec);
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void on_fork_error(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line), const bp::error_code& ec) {
        call("on_fork_error", launcher, executable, f_on_fork_error, ec);
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL bp::error_code on_exec_setup(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line)) {
        call("on_exec_setup", launcher, executable, f_on_exec_setup);
        return bp::error_code();
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void on_exec_error(Launcher& launcher, const bp::filesystem::path& executable,
            const char* const* (&cmd_line)) {
        call("on_exec_error", launcher, executable, f_on_exec_error);
    }

private:
    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void call(const char* type, Launcher& launcher, const bp::filesystem::path& executable,
            const ResolvedCallReferenceNode* callref,
            const bp::error_code& ec) const {
        if (!callref) {
            //printd(5, "no handler installed for '%s'\n", executable.c_str());
            return;
        }

        ReferenceHolder<QoreHashNode> report(new QoreHashNode(autoTypeInfo), xsink);
        report->setKeyValue("name", new QoreStringNode(type), xsink);
        report->setKeyValue("exe", new QoreStringNode(executable.c_str()), xsink);
        report->setKeyValue("pid", launcher.pid, xsink);

        // error_code to hash too
        report->setKeyValue("error_code", ec.value(), xsink);
        report->setKeyValue("error_message", new QoreStringNode(ec.message()), xsink);
        report->setKeyValue("error_category", new QoreStringNode(ec.category().name()), xsink);

        ReferenceHolder<QoreListNode> args(new QoreListNode(autoTypeInfo), xsink);
        args->push(report.release(), xsink);
        callref->execValue(*args, xsink);
    }

    template<typename Launcher = bp::posix::default_launcher>
    DLLLOCAL void call(const char* type, Launcher& launcher, const bp::filesystem::path& executable,
            const ResolvedCallReferenceNode* callref) const {
        if (!callref) {
            //printd(5, "no handler installed for '%s'\n", executable.c_str());
            return;
        }

        ReferenceHolder<QoreHashNode> report(new QoreHashNode(autoTypeInfo), xsink);
        report->setKeyValue("name", new QoreStringNode(type), xsink);
        report->setKeyValue("exe", new QoreStringNode(executable.c_str()), xsink);
        report->setKeyValue("pid", launcher.pid, xsink);

        ReferenceHolder<QoreListNode> args(new QoreListNode(autoTypeInfo), xsink);
        args->push(report.release(), xsink);
        callref->execValue(*args, xsink);
    }
};

ProcessPriv::ProcessPriv(pid_t pid, ExceptionSink* xsink) :
        m_asio_ctx(),
        m_in_pipe(m_asio_ctx),
        m_out_pipe(m_asio_ctx),
        m_err_pipe(m_asio_ctx),

        m_in_buf(&bg_xsink),
        m_out_buf(&bg_xsink),
        m_err_buf(&bg_xsink),

        m_in_asiobuf(boost::asio::buffer(m_in_vec)),
        m_out_asiobuf(boost::asio::buffer(m_out_vec)),
        m_err_asiobuf(boost::asio::buffer(m_err_vec)) {
    try {
#ifdef __APPLE__
        // check if process is valid and throw an exception is not
        if (kill(pid, 0)) {
            throw std::runtime_error("Process with PID " + std::to_string(pid) + " does not exist");
        }
#endif
        //printd(5, "ProcessPriv::ProcessPriv(pid: %d)\n", pid);
        m_process = new bp::process(m_asio_ctx.get_executor(), (boost::process::v2::pid_type)pid);
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-CONSTRUCTOR-ERROR", ex.what());
    }
}

ProcessPriv::ProcessPriv(const char* command, const QoreListNode* arguments, const QoreHashNode *opts,
        ExceptionSink* xsink) :
        m_asio_ctx(),
        m_in_pipe(m_asio_ctx),
        m_out_pipe(m_asio_ctx),
        m_err_pipe(m_asio_ctx),

        m_in_buf(&bg_xsink),
        m_out_buf(&bg_xsink),
        m_err_buf(&bg_xsink),

        m_out_vec(process_buf_size),
        m_err_vec(process_buf_size),

        m_in_asiobuf(boost::asio::buffer(m_in_vec)),
        m_out_asiobuf(boost::asio::buffer(m_out_vec)),
        m_err_asiobuf(boost::asio::buffer(m_err_vec)) {
    // parse options
    env_t env = optsEnv(opts, xsink);
    boost::filesystem::path p = optsPath(command, opts, xsink);
    std::string cwd = optsCwd(opts, xsink);

    if (xsink->isException()) {
        return;
    }

    if (opts && opts->existsKey("encoding")) {
        QoreValue n = opts->getKeyValue("encoding");
        if (n.getType() != NT_STRING) {
            xsink->raiseException("PROCESS-OPTION-ERROR", "Process option 'encoding' requires a 'string' argument; "
                "type '%s' instead", n.getTypeName());
            return;
        }
        enc = QEM.findCreate(n.get<const QoreStringNode>()->c_str());
    }

    // not yet supported; not possible to read from an input stream with a timeout or to read all data available
    //optsStdin(opts, xsink);

    int stdoutFD = optsStdout("stdout", opts, xsink);
    int stderrFD = optsStdout("stderr", opts, xsink);
    if (xsink->isException()) {
        return;
    }

    FILE* stdoutFile = nullptr;
    FILE* stderrFile = nullptr;
    if (stdoutFD != -1) {
        stdoutFile = fdopen(stdoutFD, "w");
    }
    if (stderrFD != -1) {
        stderrFile = fdopen(stderrFD, "w");
    }

    // process exe arguments
    std::vector<std::string> exeArgs;
    processArgs(arguments, exeArgs);

    // setup stdout, stderr and stdin closures
    prepareClosures();

    // launch child process
    try {
        launchChild(xsink, p, exeArgs, env, cwd.c_str(), stdoutFile, stderrFile, opts);
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-CONSTRUCTOR-ERROR", ex.what());
    }

    // stop async I/O thread immediately before obliteration if an exception was thrown
    if (*xsink) {
        finalizeStreams(xsink);
    }
}

ProcessPriv::~ProcessPriv() {
    // in case the object is obliterated (exception in constructor), the destructor is not run
    delete m_process;
    assert(!bg_xsink);
}

int ProcessPriv::destructor(ExceptionSink* xsink) {
    // rethrows any background exceptions
    finalizeStreams(xsink);

    // delete child process
    if (m_process) {
        delete m_process;
        m_process = nullptr;
    }

    return *xsink ? -1 : 0;
}

ResolvedCallReferenceNode* ProcessPriv::optsExecutor(const char* name, const QoreHashNode* oh, ExceptionSink* xsink) {
    ResolvedCallReferenceNode* ret = nullptr;

    if (oh) {
        if (oh->existsKey(name)) {
            QoreValue n = oh->getKeyValue(name);
            if (n.getType() != NT_RUNTIME_CLOSURE && n.getType() != NT_FUNCREF) {
                xsink->raiseException("PROCESS-OPTION-ERROR",
                    "executor '%s' required code as value, got: '%s'(%d)",
                    name,
                    n.getTypeName(),
                    n.getType()
                );
                return ret;
            }

            ret = n.get<ResolvedCallReferenceNode>();
            ret->refSelf();
        }
    }

    return ret;
}

env_t ProcessPriv::optsEnv(const QoreHashNode* opts, ExceptionSink* xsink) {
    // As agreed - we are not merging current process env. We are replacing.
    // The "merge" can be done with global ENV hash.
    // bp::process_environment ret = bp::environment::current();
    env_t ret;

    if (opts && opts->existsKey("env")) {
        QoreValue n = opts->getKeyValue("env");
        if (n.getType() != NT_HASH) {
            xsink->raiseException("PROCESS-OPTION-ERROR",
                "Environment variables option must be a hash, got: '%s'(%d)",
                n.getTypeName(),
                n.getType()
            );
            return ret;
        }

        ConstHashIterator it(n.get<const QoreHashNode>());
        while (it.next()) {
            QoreStringValueHelper val(it.get());
            ret[it.getKey()] = bp::environment::value(val->c_str());
        }

        return ret;
    }

    for (const auto& i : bp::environment::current()) {
        // copy the environment variables from the current process
        ret[i.key()] = i.value();
    }
    return ret;
}

std::string ProcessPriv::optsCwd(const QoreHashNode* opts, ExceptionSink* xsink) {
    std::string ret(".");

    if (opts && opts->existsKey("cwd")) {
        QoreValue n = opts->getKeyValue("cwd");
        if (n.getType() != NT_STRING) {
            xsink->raiseException("PROCESS-OPTION-ERROR",
                "Working dir 'cwd' option must be a string, got: '%s'(%d)",
                n.getTypeName(),
                n.getType()
            );
            return ret;
        }
        QoreStringValueHelper s(n);
        ret = s->c_str();
    }

    return ret;
}

void ProcessPriv::optsStdin(const QoreHashNode* opts, ExceptionSink* xsink) {
    if (!opts || !opts->existsKey("stdin")) {
        return;
    }
    QoreValue n = opts->getKeyValue("stdin");
    if (n.getType() != NT_OBJECT) {
        xsink->raiseException("PROCESS-OPTION-ERROR",
            "Process constructor option 'stdin' must be an "
            "InputStream object; got type '%s' instead",
            n.getTypeName()
        );
        return;
    }

    // if the above returns NT_OBJECT, then the following line must succeed
    QoreObject* obj = n.get<QoreObject>();

    // see if a usable class is accessible in this call
    ClassAccess access;
    bool in_hierarchy = obj->getClass()->inHierarchy(*QC_INPUTSTREAM, access);
    if (!in_hierarchy || access != Public) {
        xsink->raiseException("PROCESS-OPTION-ERROR", "Process constructor option 'stdin' expecting an object "
            "of class 'OutputStream'; got an object of class '%s' instead",
            obj->getClassName());
        return;
    }

    PrivateDataRefHolder<InputStream> stream(obj, CID_INPUTSTREAM, xsink);
    if (*xsink) {
        // an exception has already been thrown here
        xsink->appendLastDescription(" (while processing Process constructor option 'stdin' expecting "
            "a valid Inputstream object)");
        return;
    }
    stream->unassignThread(xsink);
    m_in_buf.setStream(stream.release());
}

int ProcessPriv::optsStdout(const char* keyName, const QoreHashNode* opts, ExceptionSink* xsink) {
    int ret = -1;

    if (opts && opts->existsKey(keyName)) {
        QoreValue n = opts->getKeyValue(keyName);
        if (n.getType() != NT_OBJECT) {
            xsink->raiseException("PROCESS-OPTION-ERROR",
                "Process constructor option '%s' must be a File object (open for writing) or an "
                "OutputStream object; got type '%s' instead",
                keyName,
                n.getTypeName()
            );
            return -1;
        }

        // if the above returns NT_OBJECT, then the following line must succeed
        QoreObject* obj = n.get<QoreObject>();

        // see if a usable class is accessible in this call
        {
            ClassAccess access;
            bool in_hierarchy = obj->getClass()->inHierarchy(*QC_FILE, access);
            if (!in_hierarchy || access != Public) {
                in_hierarchy = obj->getClass()->inHierarchy(*QC_OUTPUTSTREAM, access);
                if (in_hierarchy && access == Public) {
                    PrivateDataRefHolder<OutputStream> stream(obj, CID_OUTPUTSTREAM, xsink);
                    if (*xsink) {
                        // an exception has already been thrown here
                        xsink->appendLastDescription(" (while processing Process constructor option '%s' expecting "
                            "a valid OutputStream object)", keyName);
                        return -1;
                    }
                    stream->unassignThread(xsink);
                    if (!strcmp(keyName, "stdout")) {
                        m_out_buf.setStream(stream.release());
                    } else {
                        m_err_buf.setStream(stream.release());
                    }
                    return -1;
                } else {
                    xsink->raiseException("PROCESS-OPTION-ERROR", "Process constructor option '%s' expecting an object "
                        "of class 'File' or 'OutputStream'; got an object of class '%s' instead",
                        keyName,
                        obj->getClassName());
                    return -1;
                }
            }
        }

        PrivateDataRefHolder<File> file(obj, CID_FILE, xsink);
        if (*xsink) {
            // an exception has already been thrown here
            xsink->appendLastDescription(" (while processing Process constructor option '%s' expecting a valid File "
                "object open for writing)", keyName);
            return -1;
        }

        if (!file->isOpen()) {
            xsink->raiseException("PROCESS-OPTION-ERROR",
                "Process constructor option '%s' must be an open File object; the File object "
                "passed is not open for writing",
                keyName
            );
            return -1;
        }
        ret = file->detachFd();
    }

    return ret;
}

boost::filesystem::path ProcessPriv::optsPath(const char* command, const QoreHashNode* opts, ExceptionSink* xsink) {
    boost::filesystem::path ret;

    try {
        if (opts && opts->existsKey("path")) {
            QoreValue n = opts->getKeyValue("path");
            if (n.getType() != NT_LIST) {
                xsink->raiseException("PROCESS-OPTION-ERROR",
                    "Path option must be a list of strings, got: '%s'(%d)",
                    n.getTypeName(),
                    n.getType()
                );
                return ret;
            }

            const QoreListNode* l = n.get<const QoreListNode>();
            std::string paths;

            for (qore_size_t i = 0; i < l->size(); i++) {
                QoreStringValueHelper s(l->retrieveEntry(i));
                if (i) {
                    paths.append(":");
                }
                paths.append(s->c_str());
            }

            std::unordered_map<bp::environment::key, bp::environment::value> my_env = {
                {"PATH", bp::environment::value(paths)},
            };

            ret = bp::environment::find_executable(command, my_env);
        } else {
            ret = bp::environment::find_executable(command);
        }
    } catch (std::runtime_error& ex) {
        xsink->raiseException("PROCESS-SEARCH-PATH-ERROR", ex.what());
    	return ret;
    }

    if (ret.empty()) {
        // issue #2524 if the command is already absolute, then use it
        ret = command;
        if (ret.is_absolute())
            return ret;

        ret.clear();
        xsink->raiseException("PROCESS-SEARCH-PATH-ERROR", "Command '%s' cannot be found in PATH", command);
    }
    try {
        return boost::filesystem::absolute(ret);
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-DIRECTORY-ERROR", ex.what());
        return ret;
    }
}

bool ProcessPriv::processCheck(ExceptionSink* xsink) {
    if (!m_process) {
        if (xsink) {
            xsink->raiseException("PROCESS-CHECK-ERROR", "Process is not initialized");
        }
        return false;
    }
    return true;
}

bool ProcessPriv::processReadStdoutCheck(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }
    if (m_out_buf.hasStream()) {
        if (xsink) {
            xsink->raiseException("PROCESS-STREAM-ERROR", "stdout cannot be read from the process as it's attached " \
                "to an output stream");
        }
        return false;
    }
    return true;
}

bool ProcessPriv::processReadStderrCheck(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }
    if (m_err_buf.hasStream()) {
        if (xsink) {
            xsink->raiseException("PROCESS-STREAM-ERROR", "stderr cannot be read from the process as it's attached " \
                "to an output stream");
        }
        return false;
    }
    return true;
}

void ProcessPriv::processArgs(const QoreListNode* arguments, std::vector<std::string>& out) {
    if (arguments) {
        for (qore_size_t i = 0; i < arguments->size(); i++) {
            QoreStringNodeValueHelper s(arguments->retrieveEntry(i));
            // ignore empty args; causes an assert on RHEL 8 in boost arg processing
            if (!s->empty()) {
                out.push_back(s->c_str());
            }
        }
    }
}

void ProcessPriv::prepareStdinBuffer() {
    // fill stdin vector
    m_in_buf.extract(m_in_vec, 4096);

    // create new ASIO buffer
    m_in_asiobuf = boost::asio::buffer(m_in_vec);
}

void ProcessPriv::prepareClosures() {
    // stdout setup
    m_on_stdout_complete = [this](const boost::system::error_code& ec, size_t n) {
        // append read data to output buffer
        m_out_buf.append(m_out_vec.data(), n);

        // continue reading if no error
        if (!ec) {
            boost::asio::async_read(m_out_pipe, m_out_asiobuf, boost::asio::transfer_at_least(1),
                m_on_stdout_complete);
        }
    };

    // stderr setup
    m_on_stderr_complete = [this](const boost::system::error_code& ec, size_t n) {
        // append read data to output buffer
        m_err_buf.append(m_err_vec.data(), n);

        // continue reading if no error
        if (!ec) {
            boost::asio::async_read(m_err_pipe, m_err_asiobuf, boost::asio::transfer_at_least(1),
                m_on_stderr_complete);
        }
    };

    // stdin setup
    m_on_stdin_complete = [this](const boost::system::error_code& ec, size_t n) {
        std::lock_guard<std::mutex> lock(m_async_write_mtx);

        // delete already written data from stdin vector
        m_in_vec.erase(m_in_vec.begin(), m_in_vec.begin() + n);

        // check error
        if (ec) {
            --m_async_write_running;
            return;
        }

        // if there is remaining data, try to write it
        if (m_in_vec.size()) {
            m_in_asiobuf = boost::asio::buffer(m_in_vec);
            boost::asio::async_write(m_in_pipe, m_in_asiobuf, m_on_stdin_complete);
            return;
        }

        // check if there is new data ready to be written
        if (m_in_buf.size()) {
            prepareStdinBuffer();
            boost::asio::async_write(m_in_pipe, m_in_asiobuf, m_on_stdin_complete);
            return;
        }

        --m_async_write_running;
    };
}

/*
struct PreservedFds : boost::process::detail::handler, boost::process::detail::uses_handles {
    std::vector<int> fds;
    PreservedFds() : fds({0, 1, 2}) {
    }

    std::vector<int>& get_used_handles() {
        return fds;
    }
};
*/

void ProcessPriv::launchChild(ExceptionSink* xsink,
        boost::filesystem::path p,
        std::vector<std::string>& args,
        env_t env,
        const char* cwd,
        FILE* stdoutFile,
        FILE* stderrFile,
        const QoreHashNode* opts) {
    // get handler pointers
    ReferenceHolder<ResolvedCallReferenceNode> f_on_success(optsExecutor("on_success", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_setup(optsExecutor("on_setup", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_error(optsExecutor("on_error", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_fork_error(optsExecutor("on_fork_error", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_exec_setup(optsExecutor("on_exec_setup", opts, xsink), xsink);
    if (*xsink) {
        return;
    }
    ReferenceHolder<ResolvedCallReferenceNode> f_on_exec_error(optsExecutor("on_exec_error", opts, xsink), xsink);
    if (*xsink) {
        return;
    }

    callback_initializer cbi{
        *f_on_success,
        *f_on_setup,
        *f_on_error,
        *f_on_fork_error,
        *f_on_exec_setup,
        *f_on_exec_error,
        xsink
    };

    bp::process_environment penv = bp::process_environment(env);

    if (stdoutFile && stderrFile) {
        m_process = new bp::process(m_asio_ctx, p.string(), args, cbi,
            bp::process_stdio{m_in_pipe, stdoutFile, stderrFile},
            bp::process_start_dir(cwd),
            penv
        );
    } else if (stdoutFile) {
        m_process = new bp::process(m_asio_ctx, p.string(), args, cbi,
            bp::process_stdio{m_in_pipe, stdoutFile, m_err_pipe},
            bp::process_start_dir(cwd),
            penv
        );
    } else if (stderrFile) {
        m_process = new bp::process(m_asio_ctx, p.string(), args, cbi,
            bp::process_stdio{m_in_pipe, m_out_pipe, stderrFile},
            bp::process_start_dir(cwd),
            penv
        );
    } else {
        m_process = new bp::process(m_asio_ctx, p.string(), args, cbi,
            bp::process_stdio{m_in_pipe, m_out_pipe, m_err_pipe},
            bp::process_start_dir(cwd),
            penv
        );
    }

    m_process->async_wait(
        [this](boost::system::error_code ec, int e) {
            this->setExitCode(ec, e);
        }
    );

    {
        std::unique_lock<std::mutex> lock(mtx_process_status);
        assert(!running_flag);
        running_flag = true;
    }

    // create async read operations
    if (!stdoutFile) {
        boost::asio::async_read(m_out_pipe, m_out_asiobuf, boost::asio::transfer_at_least(1),
            m_on_stdout_complete);
    }
    if (!stderrFile) {
        boost::asio::async_read(m_err_pipe, m_err_asiobuf, boost::asio::transfer_at_least(1),
            m_on_stderr_complete);
    }

    // increment counter before launching thread
    stream_cnt.inc();

    // issue #4303: to avoid a race condition in async I/O where a "dup2() failed" error is raised,
    // we wait until the I/O thread is running before continuing
    QoreCounter started(1);

    // launch async operations
    m_asio_ctx_run_future = std::async(std::launch::async, [this, &started]{
        q_register_foreign_thread();
        ON_BLOCK_EXIT(q_deregister_foreign_thread);

        m_out_buf.reassignThread();
        m_err_buf.reassignThread();

        try {
            // do one non-blocking poll to ensure that everything is in place
            m_asio_ctx.poll_one();
            // signal the parent thread that background I/O is up and running
            started.dec(nullptr);
            // run the background I/O in blocking mode in the dedicated I/O thread
            m_asio_ctx.run();
        } catch (const std::exception& ex) {
            printd(0, "exception in m_asio_ctx.run() in m_asio_ctx_run_future: %s", ex.what());
        }

        m_out_buf.unassignThread();
        m_err_buf.unassignThread();

        // signal that the I/O thread has terminated
        stream_cnt.dec(nullptr);
    });

    // wait for background I/O to be up and running before continuing
    started.waitForZero(nullptr);
}

void ProcessPriv::setExitCode(boost::system::error_code ec, int e) {
    std::unique_lock<std::mutex> lock(mtx_process_status);
    //printd(5, "process::async_wait() (%d: %s) %s; setting running_flag = false (waiting: %d)\n", ec.value(),
    //    ec.category().name(), ec.message().c_str(), process_status_waiting);
    assert(running_flag);
    running_flag = false;
    if (!ec) {
        exit_code = bp::evaluate_exit_code(e);
    }
    if (process_status_waiting) {
        cond_process_status.notify_all();
    }
}

int ProcessPriv::exitCode(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return -1;
    }

    std::lock_guard<std::mutex> lock(mtx_process_status);
    return exit_code;
}

int ProcessPriv::id(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return -1;
    }

    try {
        return detached_pid ? detached_pid : m_process->id();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-ID-ERROR", ex.what());
    }

    return -1;
}

bool ProcessPriv::valid(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    return m_process->is_open();
}

bool ProcessPriv::running(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        //printd(5, "ProcessPriv::running() processCheck() failed\n");
        return false;
    }

    std::lock_guard<std::mutex> lock(mtx_process_status);
    if (exit_code != -1) {
        return false;
    }

    if (detached_pid) {
        int code = 0;
        int res = ::waitpid(detached_pid, &code, WNOHANG);
        //printd(5, "ProcessPriv::running() detached PID %d; waitpid() result: %d code: %d exited: %d signaled: %d\n",
        //    detached_pid, res, code, (int)WIFEXITED(code), (int)WIFSIGNALED(code));
        if (res == -1) {
            xsink->raiseException("PROCESS-RUNNING-ERROR", "Cannot check detached process with PID %d: %s",
                detached_pid, strerror(errno));
            return false;
        } else if (!res) {
            return true;
        }

        if (!WIFEXITED(code) && !WIFSIGNALED(code)) {
            return true;
        }
        //printd(5, "ProcessPriv::running() detached PID %d is not running; exit code: %d\n", detached_pid, code);
        exit_code = WEXITSTATUS(code);

        return false;
    }

    boost::system::error_code ec;
    bool rc = m_process->running(ec);
    // ECHILD is raised with processes created from a PID, so we check it manually
    if (!rc && (ec == std::errc::no_child_process)) {
        //printd(5, "ProcessPriv::running() ECHILD; checking manually\n");
        return checkPid(m_process->id(), xsink);
    }
    //printd(5, "ProcessPriv::running() returning %s\n", rc ? "true" : "false");
    return rc;
}

void ProcessPriv::finalizeStreams(ExceptionSink* xsink) {
    // the asio context is stopped in the process handler unless the process has been detached
    if (detached_pid) {
        m_asio_ctx.stop();
        try {
            m_asio_ctx.run();
        } catch (const std::exception& ex) {
            printd(0, "exception in m_asio_ctx.run() in ProcessPriv::finalizeStreams(): %s", ex.what());
        }
    }

    // wait for future
    if (!m_out_vec.empty() && m_asio_ctx_run_future.valid()) {
        m_asio_ctx_run_future.get();
    }

    stream_cnt.waitForZero(xsink);

    ReferenceHolder<OutputStream> out(xsink);
    ReferenceHolder<OutputStream> err(xsink);

    {
        AutoLocker al(bg_lck);
        if (bg_xsink) {
            xsink->assimilate(bg_xsink);
        }

        out = m_out_buf.finalize(xsink);
        err = m_err_buf.finalize(xsink);
    }
}

QoreStringNode* ProcessPriv::getString(QoreStringNode* str) {
    if (!enc->isMultiByte()) {
        return str;
    }

    // first prepend any buffered bytes to the string
    {
        AutoLocker al(bg_lck);
        if (!charbuf->empty()) {
            str->prepend((const char*)charbuf->getPtr(), charbuf->size());
            charbuf->clear();
        }
    }

    // check for an invalid trailing char
    bool invalid = false;
    size_t len = enc->getLength(str->c_str(), str->c_str() + str->size(), invalid);
    if (invalid) {
        printd(5, "ProcessPriv::getString() INVALID str: '%s' size: %d len: %d\n", str->c_str(), (int)str->size(), (int)len);
        assert(str->size() > len);
        // move invalid bytes to buffer
        charbuf->append(str->c_str() + len, str->size() - len);
        if (!len) {
            str->deref();
            return nullptr;
        }
        str->terminate(len);
    }
    return str;
}

void ProcessPriv::getExitCode(ExceptionSink* xsink) {
    std::lock_guard<std::mutex> lock(mtx_process_status);
    if (exit_code != -1) {
        return;
    }

    assert(m_process);
    try {
        exit_code = m_process->exit_code();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-EXITCODE-ERROR", ex.what());
    }
}

bool ProcessPriv::wait(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    // return immediately if we already have an exit code
    {
        std::lock_guard<std::mutex> lock(mtx_process_status);
        if (exit_code != -1) {
            return true;
        }
    }

    //printd(0, "ProcessPriv::wait() is_open: %d detached_pid: %d exit_code: %d\n", m_process->is_open(),
    //    detached_pid, exit_code);

    try {
        // wait on detached process
        if (detached_pid) {
            int wstatus;
            if (waitpid(detached_pid, &wstatus, 0) == -1) {
                if (errno == ECHILD) {
                    return false;
                }
                xsink->raiseException("PROCESS-WAIT-ERROR", "Cannot get exit code for detached process with PID %d: "
                    "%s", detached_pid, strerror(errno));
                return false;
            }
            std::unique_lock<std::mutex> lock(mtx_process_status);
            //printd(5, "process::async_wait() (%d: %s) %s; setting running_flag = false (waiting: %d)\n", ec.value(),
            //    ec.category().name(), ec.message().c_str(), process_status_waiting);
            exit_code = WEXITSTATUS(wstatus);
            if (process_status_waiting) {
                cond_process_status.notify_all();
            }
        } else {
            boost::system::error_code ec;
            m_process->wait(ec);
            if (ec && ec != std::errc::no_child_process) {
                xsink->raiseException("PROCESS-WAIT-ERROR", "cannot wait on process: %s", ec.message().c_str());
                return false;
            }

            if (exit_code == -1) {
                // get exit code if possible
                getExitCode(xsink);
            }
        }

        // rethrows any background exceptions
        finalizeStreams(xsink);
        return true;
    } catch (const std::exception& ex) {
        const char* err = ex.what();
        xsink->raiseException("PROCESS-WAIT-ERROR", err);
    }

    return false;
}

bool ProcessPriv::wait(int64 t, ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    // return immediately if we already have an exit code
    {
        std::lock_guard<std::mutex> lock(mtx_process_status);
        if (exit_code != -1) {
            return true;
        }
    }

    try {
        std::unique_lock<std::mutex> lock(mtx_process_status);
        if (running_flag) {
            // wait for the process to finish
            ++process_status_waiting;
            // use a predicate to handle spurious wakeups
            cond_process_status.wait_for(lock, std::chrono::milliseconds(t),
                [this] {
                    return !running_flag;
                });
            --process_status_waiting;

            if (running_flag) {
                return false;
            }
        }
        // rethrows any background exceptions
        finalizeStreams(xsink);
        return true;
    } catch (const std::exception& ex) {
        const char* err = ex.what();
        xsink->raiseException("PROCESS-WAIT-ERROR", err);
    }

    return false;
}

bool ProcessPriv::detach(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    try {
        detached_pid = m_process->id();
        m_process->detach();
    } catch (const std::exception& ex) {
        const char* err = ex.what();
        xsink->raiseException("PROCESS-WAIT-ERROR", err);
        detached_pid = 0;
        return false;
    }
    return true;
}

bool ProcessPriv::terminate(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    if (detached_pid) {
        if (kill(detached_pid, SIGKILL) == -1) {
            xsink->raiseException("PROCESS-TERMINATE-ERROR", "Cannot terminate process: %s",
                strerror(errno));
            return false;
        }
        return true;
    }

    boost::system::error_code ec;
    m_process->terminate(ec);

    //printd(5, "ProcessPriv::terminate() ec: %d (%s): %s\n", ec.value(), ec.category().name(),
    //    ec.message().c_str());

    if (ec) {
        // ECHILD is raised with the wait() call after the process has been terminated
        if (ec.value() == ECHILD) {
            std::lock_guard<std::mutex> lock(mtx_process_status);
            if (exit_code == -1) {
            }
            return true;
        }
        xsink->raiseException("PROCESS-TERMINATE-ERROR", "Cannot terminate process: (%d: %s) %s",
            ec.value(), ec.category().name(), ec.message().c_str());
        return false;
    }
    return true;
}

QoreStringNode* ProcessPriv::readStderr(size_t n, ExceptionSink* xsink) {
    if (!processReadStderrCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<QoreStringNode> str(new QoreStringNode(enc));
        size_t read = m_err_buf.read(*str, n);
        if (read)
            return getString(str.release());
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

QoreStringNode* ProcessPriv::readStderrTimeout(size_t n, int64 millis, ExceptionSink* xsink) {
    if (!processReadStderrCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<QoreStringNode> str(new QoreStringNode(enc));
        size_t read = m_err_buf.readTimeout(*str, n, millis);
        if (read)
            return getString(str.release());
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

QoreStringNode* ProcessPriv::readStdout(size_t n, ExceptionSink* xsink) {
    if (!processReadStdoutCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<QoreStringNode> str(new QoreStringNode(enc));
        size_t read = m_out_buf.read(*str, n);
        if (read)
            return getString(str.release());
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

QoreStringNode* ProcessPriv::readStdoutTimeout(size_t n, int64 millis, ExceptionSink* xsink) {
    if (!processReadStdoutCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<QoreStringNode> str(new QoreStringNode(enc));
        size_t read = m_out_buf.readTimeout(*str, n, millis);
        if (read)
            return getString(str.release());
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

BinaryNode* ProcessPriv::readStderrBinary(size_t n, ExceptionSink* xsink) {
    if (!processReadStderrCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<BinaryNode> bin(new BinaryNode);
        size_t read = m_err_buf.read(*bin, n);
        if (read)
            return bin.release();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

BinaryNode* ProcessPriv::readStderrBinaryTimeout(size_t n, int64 millis, ExceptionSink* xsink) {
    if (!processReadStderrCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<BinaryNode> bin(new BinaryNode);
        size_t read = m_err_buf.readTimeout(*bin, n, millis);
        if (read)
            return bin.release();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

BinaryNode* ProcessPriv::readStdoutBinary(size_t n, ExceptionSink* xsink) {
    if (!processReadStdoutCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<BinaryNode> bin(new BinaryNode);
        size_t read = m_out_buf.read(*bin, n);
        if (read)
            return bin.release();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

BinaryNode* ProcessPriv::readStdoutBinaryTimeout(size_t n, int64 millis, ExceptionSink* xsink) {
    if (!processReadStdoutCheck(xsink)) {
        return nullptr;
    }

    // check size to read
    if (n <= 0)
        return nullptr;

    try {
        SimpleRefHolder<BinaryNode> bin(new BinaryNode);
        size_t read = m_out_buf.readTimeout(*bin, n, millis);
        if (read)
            return bin.release();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return nullptr;
}

void ProcessPriv::write(const char* val, size_t n, ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return;
    }

    if (!val || !n)
        return;

    // write data to internal buffer
    m_in_buf.write(val, n);

    // check if there is async_write operation running
    std::lock_guard<std::mutex> lock(m_async_write_mtx);
    if (m_async_write_running)
        return;

    // if there is not, start a new one
    prepareStdinBuffer();
    boost::asio::async_write(m_in_pipe, m_in_asiobuf, m_on_stdin_complete);
    ++m_async_write_running;
}

#ifdef __linux__
#include <cstring>
#include <inttypes.h>
#include <sys/user.h>

QoreHashNode* ProcessPriv::getMemorySummaryInfoLinux(int pid, ExceptionSink* xsink) {
    // open memory map for file
    QoreFile f;

    {
        QoreStringMaker str("/proc/%d/statm", pid);
        if (f.open(str.c_str())) {
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read process status for PID %d", pid);
            return nullptr;
        }
    }

    int64 vsz = 0;
    int64 rss = 0;

    QoreString l;
    if (!f.readLine(l)) {
        // format: vsz rss shared text lib data dt
        // find space after vsz
        qore_offset_t pos = l.find(' ');
        assert(pos != -1);
        // find space after rss
        qore_offset_t pos1 = l.find(' ', pos + 1);
        l.terminate(pos1);
        rss = strtoll(l.c_str() + pos + 1, nullptr, 10) * page_size;
        l.terminate(pos);
        vsz = l.toBigInt() * page_size;
    }

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclMemorySummaryInfo, xsink), xsink);

    rv->setKeyValue("vsz", vsz, xsink);
    rv->setKeyValue("rss", rss, xsink);

    {
        QoreStringMaker str("/proc/%d/smaps", pid);
        if (f.open(str.c_str())) {
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read virtual shared memory map '%s' for PID %d", str.c_str(), pid);
            return nullptr;
        }
    }

    int64 priv_size = 0;
    bool need_line = true;

    while (true) {
        if (need_line && f.readLine(l)) {
            break;
        }

        // smaps map line format: 0=start-end 1=perms 2=offset 3=device 4=inode 5=pathname
        // ex: 01f1c000-01f3d000 rw-p 00000000 00:00 0                                  [heap]

        // find memory range separator
        qore_offset_t pos = l.find('-');
        assert(pos != -1);

        // find end of memory range
        qore_offset_t pos1 = l.find(' ', pos + 1);
        assert(pos1 != -1);

        int64 segment_size = 0;

        size_t start;
        {
            QoreString num(&l, pos);
            start = strtoll(num.c_str(), nullptr, 16);
        }

        size_t end;
        {
            QoreString num(l.c_str() + pos + 1, pos1 - pos - 1);
            end = strtoll(num.c_str(), nullptr, 16);
        }

        // get end of offset
        pos = l.find(' ', pos1 + 6);
        assert(pos != -1);

        // get end of device
        pos = l.find(' ', pos + 1);
        assert(pos != -1);

        // get end of inode
        pos1 = l.find(' ', ++pos);

        segment_size = (end - start);

        // read in segment attributes
        size_t pss = 0;
        bool eof = false;
        while (true) {
            if (f.readLine(l)) {
                eof = true;
                break;
            }

            if (islower(l[0])) {
                need_line = false;
                break;
            }

            if (segment_size && l.equalPartial("Pss:")) {
                QoreString num(l.c_str() + 4);
                pss = strtoll(num.c_str(), nullptr, 10);
                priv_size += pss * 1024;
                //printd(5, "smaps: segment referenced size: %lld '%s'\n", priv_size, num.c_str());
                continue;
            }

            if (l.equalPartial("VmFlags:")) {
                break;
            }
        }
        if (eof) {
            break;
        }
    }

    rv->setKeyValue("priv", priv_size, xsink);

    return rv.release();
}
#endif

#if defined(__APPLE__) && defined(__MACH__)
#include <libproc.h>

#include <mach/mach_init.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <mach/mach_vm.h>
#include <mach/mach_port.h>
#include <mach/vm_region.h>
#include <mach/vm_page_size.h>

QoreHashNode* ProcessPriv::getMemorySummaryInfoDarwin(int pid, ExceptionSink* xsink) {
    // we use proc_taskinfo() to get VSZ and RSS, but only PRIV is interesting for us
    struct proc_taskinfo taskinfo;

    int rc = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskinfo, sizeof(taskinfo));
    if (rc <= 0) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "proc_pidinfo() returned %d", rc);
        return nullptr;
    }

    //printd(5, "proc_pidinfo() rc %d vsz: " QLLD " rss: " QLLD "\n", rc, taskinfo.pti_virtual_size, taskinfo.pti_resident_size);

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclMemorySummaryInfo, xsink), xsink);

    rv->setKeyValue("vsz", taskinfo.pti_virtual_size, xsink);
    rv->setKeyValue("rss", taskinfo.pti_resident_size, xsink);

    // NOTE: task_for_pid() requires special permissions to get a task port for any task except
    // the current PID; root can do it, or the process can have a special entitlement that allows
    // any task to be acquired.  The entitlement required for this is: com.apple.system-task-ports
    // (ex: codesign -d --entitlements - /usr/bin/vmmap)
    mach_port_t task;
    // do not free the port allocated here
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "task_for_pid() returned %d: %s", (int)kr, mach_error_string(kr));
        return nullptr;
    }

    size_t priv_size = 0;
    mach_vm_address_t addr = 0;

    while (true) {
        // this approach of determining private memory per process is taken from the Darwin top sources:
        // https://opensource.apple.com/source/top/top-111.1.1/
        vm_region_top_info_data_t info;
        mach_msg_type_number_t count = VM_REGION_TOP_INFO_COUNT;
        mach_vm_size_t vmsize = 0;
        memory_object_name_t object_name;

        kr = mach_vm_region(task, &addr, &vmsize, VM_REGION_TOP_INFO,
            (vm_region_info_t)&info, &count, &object_name);
        if (kr == KERN_INVALID_ADDRESS)
            break;
        if (kr != KERN_SUCCESS) {
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "mach_vm_region() returned %d: %s", (int)kr, mach_error_string(kr));
            return nullptr;
        }
        //printd(0, "addr: %p size: %ld share_mode: %d\n", addr, vmsize, info.share_mode);
        // should not happen
        if (!vmsize) {
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "mach_vm_region() returned vmsize 0");
            return nullptr;
        }

        if (info.share_mode == SM_COW && info.ref_count == 1) {
            // Treat single reference SM_COW as SM_PRIVATE
            info.share_mode = SM_PRIVATE;
        }

        switch (info.share_mode) {
            case SM_LARGE_PAGE:
                // Treat SM_LARGE_PAGE the same as SM_PRIVATE
                // since they are not shareable and are wired.
            case SM_PRIVATE:
                priv_size += vmsize;
                break;

            // Darwin's top has a more complicated method of processing SM_COW
            // but we are not interested in kernel processes etc
            case SM_COW:
                priv_size += info.private_pages_resident * vm_kernel_page_size;
                break;
        }

        addr = addr + vmsize;
        if (!addr)
            break;
    }

    rv->setKeyValue("priv", priv_size, xsink);

    return rv.release();
}

#endif

#ifdef __sun__
#include <libproc.h>
#include <procfs.h>
QoreHashNode* ProcessPriv::getMemorySummaryInfoSolaris(int pid, ExceptionSink* xsink) {
    psinfo_t psp;
    prmap_t prp;
    size_t vsz, rss;
    size_t priv_size = 0;
    ssize_t read_ret;
    int prmap_fd;

    if (proc_get_psinfo(pid, &psp) == -1) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "proc_get_psinfo could not read process status for PID %d", pid);
        return nullptr;
    }

    QoreStringMaker prmap_path("/proc/%d/map", pid);
    prmap_fd = open(prmap_path.c_str(), O_RDONLY);
    if (prmap_fd == -1) {
        xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not open virtual shared memory map '%s' for PID %d", prmap_path.c_str(), pid);
        return nullptr;
    }

    while ((read_ret = read(prmap_fd, &prp, sizeof(prp))) == sizeof(prp)) {
        if ((prp.pr_mflags & MA_SHARED) == 0) {
            priv_size += prp.pr_size;
        }
    }

    switch (read_ret) {
        case 0:
            break;
        case -1:
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read virtual shared memory map '%s' for PID %d", prmap_path.c_str(), pid);
            close(prmap_fd);
            return nullptr;
            break;
        default:
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "failed to read a prmap structure from '%s' for PID %d, only read %d bytes\n", prmap_path.c_str(), pid, read_ret);
            close(prmap_fd);
            return nullptr;
    }

    close(prmap_fd);

    vsz = psp.pr_size * 1024;
    rss = psp.pr_rssize * 1024;

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclMemorySummaryInfo, xsink), xsink);

    rv->setKeyValue("vsz", vsz, xsink);
    rv->setKeyValue("rss", rss, xsink);
    rv->setKeyValue("priv", priv_size, xsink);

    return rv.release();
}
#endif

QoreHashNode* ProcessPriv::getMemorySummaryInfo(int pid, ExceptionSink* xsink) {
#ifdef __linux__
    return getMemorySummaryInfoLinux(pid, xsink);
#elif defined(__APPLE__) && defined(__MACH__)
    return getMemorySummaryInfoDarwin(pid, xsink);
#elif defined(__sun__)
    return getMemorySummaryInfoSolaris(pid, xsink);
#else
    xsink->raiseException("PROCESS-GETMEMORYINFO-UNSUPPORTED-ERROR", "this call is not supported on this platform");
    return nullptr;
#endif
}

bool ProcessPriv::checkPid(int pid, ExceptionSink* xsink) {
#ifdef HAVE_KILL
    return !kill(pid, 0);
#else
    xsink->raiseException("PROCESS-CHECKPID-UNSUPPORTED-ERROR", "this call is not supported on this platform");
    return false;
#endif
}

#ifdef HAVE_KILL
#include <unistd.h>
#include <sys/wait.h>

// 250ms poll interval when waiting for a process to terminate
#define WAIT_POLL_US 250000
#endif

void ProcessPriv::terminate(int pid, ExceptionSink* xsink) {
#ifdef HAVE_KILL
    if (kill(pid, SIGKILL)) {
        switch (errno) {
            case EPERM:
                xsink->raiseException("PROCESS-TERMINATE-ERROR", "insufficient permissions to terminate PID %d", pid);
                break;
            case ESRCH:
            default:
                xsink->raiseErrnoException("PROCESS-INVALID-PID", errno, "no process with PID %d can be found", pid);
                break;
        }
    }
    // now we call waitpid in case the program killed was a child process
    // in case not, errors are ignored here
    int status;
    ::waitpid(pid, &status, 0);
#else
    xsink->raiseException("PROCESS-TERMINATE-UNSUPPORTED-ERROR", "this call is not supported on this platform");
#endif
}

void ProcessPriv::waitForTermination(int pid, ExceptionSink* xsink) {
#ifdef HAVE_KILL
    while (true) {
        if (kill(pid, 0))
            break;
        usleep(WAIT_POLL_US);
    }
#else
    xsink->raiseException("PROCESS-WAITFORTERMINATION-UNSUPPORTED-ERROR", "this call is not supported on this platform");
#endif
}
