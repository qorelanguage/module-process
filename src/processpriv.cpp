/*
    Qore Programming Language process Module

    Copyright (C) 2003 - 2021 Qore Technologies, s.r.o.

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
#include "qoreprocesshandler.h"
#include "unix-config.h"

namespace bp = boost::process;
namespace ex = boost::process::extend;

DLLLOCAL extern const TypedHashDecl* hashdeclMemorySummaryInfo;

static int page_size = sysconf(_SC_PAGESIZE);

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
        int i = boost::numeric_cast<int>(pid);
        m_process = new bp::child(i);
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-CONSTRUCTOR-ERROR", ex.what());
    }
}

// default I/O buffer size
static constexpr unsigned process_buf_size = 4096;

ProcessPriv::ProcessPriv(const char* command, const QoreListNode* arguments, const QoreHashNode *opts, ExceptionSink* xsink) :
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
    // get handler pointers
    ResolvedCallReferenceNode* on_success = optsExecutor("on_success", opts, xsink);
    ResolvedCallReferenceNode* on_setup = optsExecutor("on_setup", opts, xsink);
    ResolvedCallReferenceNode* on_error = optsExecutor("on_error", opts, xsink);
    ResolvedCallReferenceNode* on_fork_error = optsExecutor("on_fork_error", opts, xsink);
    ResolvedCallReferenceNode* on_exec_setup = optsExecutor("on_exec_setup", opts, xsink);
    ResolvedCallReferenceNode* on_exec_error = optsExecutor("on_exec_error", opts, xsink);

    // parse options
    bp::environment env = optsEnv(opts, xsink);
    boost::filesystem::path p = optsPath(command, opts, xsink);
    std::string cwd = optsCwd(opts, xsink);

    if (xsink->isException()) {
        return;
    }

    if (opts && opts->existsKey("encoding")) {
        QoreValue n = opts->getKeyValue("encoding");
        if (n.getType() != NT_STRING) {
            xsink->raiseException("PROCESS-OPTION-ERROR", "Process option 'encoding' requires a 'string' argument; " \
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
        QoreProcessHandler handler(xsink,
                                   on_success,
                                   on_setup,
                                   on_error,
                                   on_fork_error,
                                   on_exec_setup,
                                   on_exec_error);

        launchChild(p, exeArgs, env, cwd.c_str(), handler, stdoutFile, stderrFile, xsink);
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

bp::environment ProcessPriv::optsEnv(const QoreHashNode* opts, ExceptionSink* xsink) {
    // As agreed - we are not merging current process env. We are replacing.
    // The "merge" can be done with global ENV hash.
    // bp::environment ret = boost::this_process::environment();
    bp::environment ret;

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
            ret[it.getKey()] = val->c_str();
        }

        return ret;
    } else {
        return boost::this_process::environment();
    }
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
                                "Process constructor option 'stdin' must be an " \
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
        xsink->raiseException("PROCESS-OPTION-ERROR", "Process constructor option 'stdin' expecting an object " \
            "of class 'OutputStream'; got an object of class '%s' instead",
            obj->getClassName());
        return;
    }

    PrivateDataRefHolder<InputStream> stream(obj, CID_INPUTSTREAM, xsink);
    if (*xsink) {
        // an exception has already been thrown here
        xsink->appendLastDescription(" (while processing Process constructor option 'stdin' expecting " \
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
                                  "Process constructor option '%s' must be a File object (open for writing) or an " \
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
                        xsink->appendLastDescription(" (while processing Process constructor option '%s' expecting " \
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
                    xsink->raiseException("PROCESS-OPTION-ERROR", "Process constructor option '%s' expecting an object " \
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
            xsink->appendLastDescription(" (while processing Process constructor option '%s' expecting a valid File " \
                "object open for writing)", keyName);
            return -1;
        }

        if (!file->isOpen()) {
            xsink->raiseException("PROCESS-OPTION-ERROR",
                                  "Process constructor option '%s' must be an open File object; the File object " \
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
            std::vector<boost::filesystem::path> paths;

            for (qore_size_t i = 0; i < l->size(); i++) {
                QoreStringValueHelper s(l->retrieveEntry(i));
                paths.push_back(boost::filesystem::path(s->c_str()));
            }

            ret = bp::search_path(command, paths);
        }
        else {
            ret = bp::search_path(command);
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

void ProcessPriv::launchChild(boost::filesystem::path p,
                             std::vector<std::string>& args,
                             bp::environment env,
                             const char* cwd,
                             QoreProcessHandler& handler,
                             FILE* stdoutFile,
                             FILE* stderrFile,
                             ExceptionSink* xsink) {
    if (stdoutFile && stderrFile) {
        m_process = new bp::child(bp::exe = p.string(),
                                  bp::args = args,
                                  bp::env = env,
                                  bp::start_dir = cwd,
                                  handler,
                                  bp::std_out > stdoutFile,
                                  bp::std_err > stderrFile,
                                  bp::std_in < m_in_pipe,
                                  m_asio_ctx);
    } else if (stdoutFile) {
        m_process = new bp::child(bp::exe = p.string(),
                                  bp::args = args,
                                  bp::env = env,
                                  bp::start_dir = cwd,
                                  handler,
                                  bp::std_out > stdoutFile,
                                  bp::std_err > m_err_pipe,
                                  bp::std_in < m_in_pipe,
                                  m_asio_ctx);
    } else if (stderrFile) {
        m_process = new bp::child(bp::exe = p.string(),
                                  bp::args = args,
                                  bp::env = env,
                                  bp::start_dir = cwd,
                                  handler,
                                  bp::std_out > m_out_pipe,
                                  bp::std_err > stderrFile,
                                  bp::std_in < m_in_pipe,
                                  m_asio_ctx);
    } else {
        m_process = new bp::child(bp::exe = p.string(),
                                  bp::args = args,
                                  bp::env = env,
                                  bp::start_dir = cwd,
                                  handler,
                                  bp::std_out > m_out_pipe,
                                  bp::std_err > m_err_pipe,
                                  bp::std_in < m_in_pipe,
                                  m_asio_ctx);
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

    // launch async operations
    m_asio_ctx_run_future = std::async(std::launch::async, [this]{
        q_register_foreign_thread();
        ON_BLOCK_EXIT(q_deregister_foreign_thread);

        m_out_buf.reassignThread();
        m_err_buf.reassignThread();

        try {
            m_asio_ctx.run();
        } catch (const std::exception& ex) {
            printd(0, "exception in m_asio_ctx.run() in m_asio_ctx_run_future: %s", ex.what());
        }

        m_out_buf.unassignThread();
        m_err_buf.unassignThread();

        stream_cnt.dec(nullptr);
    });
}

int ProcessPriv::exitCode(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return -1;
    }

    return exit_code;
}

int ProcessPriv::id(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return -1;
    }

    try {
        return m_process->id();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-ID-ERROR", ex.what());
    }

    return -1;
}

bool ProcessPriv::valid(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    try {
        return m_process->valid();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-VALID-ERROR", ex.what());
    }

    return false;
}

bool ProcessPriv::running(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    std::error_code ec;
    bool rc = m_process->running(ec);
    if (ec) {
        xsink->raiseException("PROCESS-RUNNING-ERROR", "Process::running() failed: %s", ec.message().c_str());
    }
    return rc;
}

void ProcessPriv::finalizeStreams(ExceptionSink* xsink) {
    // the asio context is stopped in the process handler unless the proces has been detached
    if (detached) {
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
    if (exit_code != -1) {
        return true;
    }

    try {
        if (m_process->valid()) {
            std::error_code ec;
            m_process->wait(ec);
            if (ec) {
                xsink->raiseException("PROCESS-WAIT-ERROR", "cannot wait on process: %s", ec.message().c_str());
                return false;
            }

            // get exit code if possible
            getExitCode(xsink);

            // rethrows any background exceptions
            finalizeStreams(xsink);
        }
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
    if (exit_code != -1) {
        return true;
    }

    try {
        if (m_process->valid()) {
            std::error_code ec;
            bool rv = m_process->wait_for(std::chrono::milliseconds(t), ec);
            if (ec) {
                xsink->raiseException("PROCESS-WAIT-ERROR", "cannot wait on process: %s", ec.message().c_str());
                return false;
            }
            if (rv) {
                // get exit code if possible
                getExitCode(xsink);

                // rethrows any background exceptions
                finalizeStreams(xsink);

                return true;
            }
        }
        return false;
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
        m_process->detach();
    } catch (const std::exception& ex) {
        const char* err = ex.what();
        xsink->raiseException("PROCESS-WAIT-ERROR", err);
        return false;
    }
    detached = true;
    return true;
}

bool ProcessPriv::terminate(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    std::error_code ec;
    m_process->terminate(ec);
    if (ec) {
        xsink->raiseException("PROCESS-TERMINATE-ERROR", "cannot terminate process: %s", ec.message().c_str());
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

QoreHashNode* ProcessPriv::getMemorySummaryInfo(int pid, ExceptionSink* xsink) {
#ifdef __linux__
    return getMemorySummaryInfoLinux(pid, xsink);
#elif defined(__APPLE__) && defined(__MACH__)
    return getMemorySummaryInfoDarwin(pid, xsink);
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
    xsink->raiseException("HAVE_PROCESS_WAITFORTERMINATION", "this call is not supported on this platform");
#endif
}
