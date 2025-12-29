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
#include <dirent.h>

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

// Resource limit settings
struct resource_limits {
    bool hasMemory = false;
    rlim_t memory = 0;
    bool hasData = false;
    rlim_t data = 0;
    bool hasStack = false;
    rlim_t stack = 0;
    bool hasCore = false;
    rlim_t core = 0;
    bool hasCpu = false;
    rlim_t cpu = 0;
    bool hasFiles = false;
    rlim_t files = 0;
    bool hasProcesses = false;
    rlim_t processes = 0;
};

struct callback_initializer {
    ResolvedCallReferenceNode* f_on_success;
    ResolvedCallReferenceNode* f_on_setup;
    ResolvedCallReferenceNode* f_on_error;
    ResolvedCallReferenceNode* f_on_fork_error;
    ResolvedCallReferenceNode* f_on_exec_setup;
    ResolvedCallReferenceNode* f_on_exec_error;
    ExceptionSink* xsink;
    bool setNice = false;
    int niceValue = 0;
    resource_limits limits;

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
        // Make this process its own process group leader to isolate it from the parent's
        // process group. This prevents signals sent to the child's process group from
        // affecting the parent and other processes in the parent's group.
        setpgid(0, 0);

        // Set process priority if requested
        if (setNice) {
            errno = 0;
            if (nice(niceValue) == -1 && errno != 0) {
                // nice() can return -1 on success if the new priority is -1
                // so we need to check errno
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        // Set resource limits if requested
        struct rlimit rl;

        if (limits.hasMemory) {
            rl.rlim_cur = rl.rlim_max = limits.memory;
            if (setrlimit(RLIMIT_AS, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        if (limits.hasData) {
            rl.rlim_cur = rl.rlim_max = limits.data;
            if (setrlimit(RLIMIT_DATA, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        if (limits.hasStack) {
            rl.rlim_cur = rl.rlim_max = limits.stack;
            if (setrlimit(RLIMIT_STACK, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        if (limits.hasCore) {
            rl.rlim_cur = rl.rlim_max = limits.core;
            if (setrlimit(RLIMIT_CORE, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        if (limits.hasCpu) {
            rl.rlim_cur = rl.rlim_max = limits.cpu;
            if (setrlimit(RLIMIT_CPU, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

        if (limits.hasFiles) {
            rl.rlim_cur = rl.rlim_max = limits.files;
            if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }

#ifdef RLIMIT_NPROC
        if (limits.hasProcesses) {
            rl.rlim_cur = rl.rlim_max = limits.processes;
            if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
                return bp::error_code(errno, boost::system::system_category());
            }
        }
#endif

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

    // Handle shell option - wrap command in sh -c
    bool useShell = false;
    std::string shellCommand;
    if (opts && opts->existsKey("shell")) {
        QoreValue n = opts->getKeyValue("shell");
        useShell = n.getAsBool();
    }

    // Handle nice option
    int niceValue = 0;
    bool setNice = false;
    if (opts && opts->existsKey("nice")) {
        QoreValue n = opts->getKeyValue("nice");
        if (n.getType() != NT_INT) {
            xsink->raiseException("PROCESS-OPTION-ERROR", "Process option 'nice' requires an 'int' argument; "
                "type '%s' instead", n.getTypeName());
            return;
        }
        niceValue = (int)n.getAsBigInt();
        setNice = true;
        // Validate nice range
        if (niceValue < -20 || niceValue > 19) {
            xsink->raiseException("PROCESS-OPTION-ERROR", "Process option 'nice' must be between -20 and 19; "
                "got %d", niceValue);
            return;
        }
    }

    // Handle resource limits option
    resource_limits limits;
    if (opts && opts->existsKey("limits")) {
        QoreValue n = opts->getKeyValue("limits");
        if (n.getType() != NT_HASH) {
            xsink->raiseException("PROCESS-OPTION-ERROR", "Process option 'limits' requires a 'hash' argument; "
                "type '%s' instead", n.getTypeName());
            return;
        }
        const QoreHashNode* limitsHash = n.get<const QoreHashNode>();

        if (limitsHash->existsKey("memory")) {
            limits.hasMemory = true;
            limits.memory = (rlim_t)limitsHash->getKeyValue("memory").getAsBigInt();
        }
        if (limitsHash->existsKey("data")) {
            limits.hasData = true;
            limits.data = (rlim_t)limitsHash->getKeyValue("data").getAsBigInt();
        }
        if (limitsHash->existsKey("stack")) {
            limits.hasStack = true;
            limits.stack = (rlim_t)limitsHash->getKeyValue("stack").getAsBigInt();
        }
        if (limitsHash->existsKey("core")) {
            limits.hasCore = true;
            limits.core = (rlim_t)limitsHash->getKeyValue("core").getAsBigInt();
        }
        if (limitsHash->existsKey("cpu")) {
            limits.hasCpu = true;
            limits.cpu = (rlim_t)limitsHash->getKeyValue("cpu").getAsBigInt();
        }
        if (limitsHash->existsKey("files")) {
            limits.hasFiles = true;
            limits.files = (rlim_t)limitsHash->getKeyValue("files").getAsBigInt();
        }
        if (limitsHash->existsKey("processes")) {
            limits.hasProcesses = true;
            limits.processes = (rlim_t)limitsHash->getKeyValue("processes").getAsBigInt();
        }
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
        if (!stdoutFile) {
            close(stdoutFD);
            xsink->raiseErrnoException("PROCESS-CONSTRUCTOR-ERROR", errno, "failed to create stdout FILE stream");
            return;
        }
    }
    if (stderrFD != -1) {
        stderrFile = fdopen(stderrFD, "w");
        if (!stderrFile) {
            if (stdoutFile) {
                fclose(stdoutFile);
            }
            close(stderrFD);
            xsink->raiseErrnoException("PROCESS-CONSTRUCTOR-ERROR", errno, "failed to create stderr FILE stream");
            return;
        }
    }

    // process exe arguments
    std::vector<std::string> exeArgs;
    boost::filesystem::path effectivePath = p;

    if (useShell) {
        // Build shell command: sh -c "command arg1 arg2 ..."
        shellCommand = p.string();
        if (arguments) {
            ConstListIterator li(arguments);
            while (li.next()) {
                shellCommand += " ";
                QoreStringValueHelper str(li.getValue());
                shellCommand += str->c_str();
            }
        }
        // Use shell as the executable
        effectivePath = "/bin/sh";
        exeArgs.push_back("-c");
        exeArgs.push_back(shellCommand);
    } else {
        processArgs(arguments, exeArgs);
    }

    // setup stdout, stderr and stdin closures
    prepareClosures();

    // launch child process
    try {
        launchChild(xsink, effectivePath, exeArgs, env, cwd.c_str(), stdoutFile, stderrFile, opts, setNice, niceValue, limits);
    } catch (const std::exception& ex) {
        // Clean up FILE handles on error
        if (stdoutFile) {
            fclose(stdoutFile);
        }
        if (stderrFile) {
            fclose(stderrFile);
        }
        xsink->raiseException("PROCESS-CONSTRUCTOR-ERROR", ex.what());
    }

    // stop async I/O thread immediately before obliteration if an exception was thrown
    if (*xsink) {
        // Clean up FILE handles on error from launchChild
        if (stdoutFile) {
            fclose(stdoutFile);
        }
        if (stderrFile) {
            fclose(stderrFile);
        }
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
        const QoreHashNode* opts,
        bool setNice,
        int niceValue,
        const resource_limits& limits) {
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
        xsink,
        setNice,
        niceValue,
        limits
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
        while (true) {
            int res = ::waitpid(detached_pid, &code, WNOHANG);
            //printd(5, "ProcessPriv::running() detached PID %d; waitpid() result: %d code: %d exited: %d signaled: %d\n",
            //    detached_pid, res, code, (int)WIFEXITED(code), (int)WIFSIGNALED(code));
            if (res == -1) {
                if (errno == EINTR) {
                    // interrupted by a signal, try again
                    continue;
                }
                // if waitpid() returns -1 with errno == ECHILD, then the process has already exited
                if (errno != ECHILD) {
                    xsink->raiseException("PROCESS-RUNNING-ERROR", "Cannot check detached process with PID %d: %s",
                        detached_pid, strerror(errno));
                }
                return false;
            } else if (!res) {
                return true;
            }
            break;
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
            while (true) {
                if (waitpid(detached_pid, &wstatus, 0) == -1) {
                    if (errno == ECHILD) {
                        return false;
                    }
                    if (errno == EINTR) {
                        continue;
                    }
                    xsink->raiseException("PROCESS-WAIT-ERROR", "Cannot get exit code for detached process with "
                        "PID %d: %s", detached_pid, strerror(errno));
                    return false;
                }
                break;
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

bool ProcessPriv::sendSignal(int sig, ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

#ifdef HAVE_KILL
    int pid = detached_pid ? detached_pid : m_process->id();
    // CRITICAL: Validate PID before calling kill()
    // If pid is -1 (invalid/moved-from process), kill(-1, sig) would kill ALL user processes!
    if (pid <= 0) {
        xsink->raiseException("PROCESS-SIGNAL-ERROR", "cannot send signal to invalid process (pid=%d)", pid);
        return false;
    }
    if (kill(pid, sig) == -1) {
        switch (errno) {
            case EPERM:
                xsink->raiseException("PROCESS-SIGNAL-ERROR", "insufficient permissions to send signal %d to PID %d",
                    sig, pid);
                break;
            case ESRCH:
                xsink->raiseException("PROCESS-SIGNAL-ERROR", "process with PID %d does not exist", pid);
                break;
            default:
                xsink->raiseErrnoException("PROCESS-SIGNAL-ERROR", errno, "cannot send signal %d to PID %d", sig, pid);
                break;
        }
        return false;
    }
    return true;
#else
    xsink->raiseException("PROCESS-SIGNAL-UNSUPPORTED-ERROR", "sending signals is not supported on this platform");
    return false;
#endif
}

bool ProcessPriv::terminate(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    if (detached_pid) {
        // CRITICAL: Validate PID before calling kill()
        if (detached_pid <= 0) {
            xsink->raiseException("PROCESS-TERMINATE-ERROR", "cannot terminate invalid process (pid=%d)", detached_pid);
            return false;
        }
        if (kill(detached_pid, SIGKILL) == -1) {
            xsink->raiseException("PROCESS-TERMINATE-ERROR", "Cannot terminate process: %s",
                strerror(errno));
            return false;
        }
        return true;
    }

    // CRITICAL: Validate PID before calling boost::process terminate
    // boost::process::terminate() directly calls kill(pid, SIGKILL) without validation
    // If pid is -1 (invalid/moved-from process), this would kill ALL user processes!
    int pid = m_process->id();
    if (pid <= 0) {
        xsink->raiseException("PROCESS-TERMINATE-ERROR", "cannot terminate invalid process (pid=%d)", pid);
        return false;
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
                // Process was killed by signal, set exit code to indicate termination
                exit_code = 128 + SIGKILL;
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

void ProcessPriv::closeStdin(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return;
    }

    // wait for any pending writes to complete
    {
        std::unique_lock<std::mutex> lock(m_async_write_mtx);
        // wait for pending writes to complete (simple spin with sleep)
        while (m_async_write_running > 0) {
            lock.unlock();
            usleep(1000);  // 1ms
            lock.lock();
        }
    }

    // close the stdin pipe
    boost::system::error_code ec;
    m_in_pipe.close(ec);
    if (ec) {
        xsink->raiseException("PROCESS-CLOSESTDIN-ERROR", "failed to close stdin pipe: %s", ec.message().c_str());
    }
}

#ifdef __linux__
#include <cstring>
#include <inttypes.h>
#include <sys/user.h>

constexpr size_t BUFSIZE = 4096;
constexpr int TIMEOUT_MS = 1000; // 1 second timeout for reading

QoreHashNode* ProcessPriv::getMemorySummaryInfoLinux(int pid, ExceptionSink* xsink) {
    // open memory map for file
    QoreFile f(QCS_USASCII);

    {
        QoreStringMaker str("/proc/%d/statm", pid);
        if (f.open(str.c_str())) {
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read process status for "
                "PID %d", pid);
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
        // see if this kernel support /proc/PID/smaps_rollup
        QoreStringMaker str("/proc/%d/smaps_rollup", pid);
        if (f.open(str.c_str())) {
            // if not, try to read /proc/PID/smaps
            return getMemorySummaryInfoLinuxSmaps(xsink, pid, f, rv);
        }
    }

    SimpleRefHolder<QoreStringNode> str(new QoreStringNode(QCS_USASCII));
    char buf[BUFSIZE];

    while (true) {
        size_t len = f.read(buf, BUFSIZE, TIMEOUT_MS, xsink);
        if (*xsink) {
            return nullptr;
        }
        if (!len) {
            break;
        }
        str->concat(buf, len);
    }

    if (!str->size()) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "Could not read memory map for PID %d", pid);
        return nullptr;
    }

    ssize_t pos = str->find("Pss:");
    if (pos == -1) {
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "Could not find PSS in memory map for PID %d", pid);
        return nullptr;
    }
    // get PSS value
    pos += 2; // skip "PSS:"
    char c;
    do {
        ++pos;
        c = (**str)[pos];
        if (!c) {
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "PSS value missing in memory map for PID %d", pid);
            return nullptr;
        }
    } while (!isdigit(c));

    // read in PSS value
    int64 pss = strtoll(str->c_str() + pos, nullptr, 10) * 1024; // convert to bytes

    rv->setKeyValue("priv", pss, xsink);

    return rv.release();
}

QoreHashNode* ProcessPriv::getMemorySummaryInfoLinuxSmaps(ExceptionSink* xsink, int pid, QoreFile& f,
        ReferenceHolder<QoreHashNode>& rv) {
    {
        QoreStringMaker str("/proc/%d/smaps", pid);
        if (f.open(str.c_str())) {
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read virtual shared memory "
                "map '%s' for PID %d", str.c_str(), pid);
            return nullptr;
        }
    }

    int64 priv_size = 0;
    bool need_line = true;

    // FIXME: reading smaps line by line will result in an inconsistnt result; the entire smap needs to be read into
    // a single buffer in one read, but the kernel buffer is not big enough to allow this in many cases, so this
    // version if inherently unreliable in any case
    while (true) {
        QoreString l;
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

    //printd(5, "proc_pidinfo() rc %d vsz: " QLLD " rss: " QLLD "\n", rc, taskinfo.pti_virtual_size,
    //    taskinfo.pti_resident_size);

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
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "task_for_pid() returned %d: %s", (int)kr,
            mach_error_string(kr));
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
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "mach_vm_region() returned %d: %s", (int)kr,
                mach_error_string(kr));
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
        xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "proc_get_psinfo could not read process status for "
            "PID %d", pid);
        return nullptr;
    }

    QoreStringMaker prmap_path("/proc/%d/map", pid);
    prmap_fd = open(prmap_path.c_str(), O_RDONLY);
    if (prmap_fd == -1) {
        xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not open virtual shared memory "
            "map '%s' for PID %d", prmap_path.c_str(), pid);
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
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read virtual shared memory "
                "map '%s' for PID %d", prmap_path.c_str(), pid);
            close(prmap_fd);
            return nullptr;
            break;
        default:
            xsink->raiseException("PROCESS-GETMEMORYINFO-ERROR", "failed to read a prmap structure from '%s' for "
                "PID %d, only read %d bytes\n", prmap_path.c_str(), pid, read_ret);
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
    while (true) {
        int res = ::waitpid(pid, &status, 0);
        if ((res == -1) && (errno == EINTR)) {
            continue;
        }
        break;
    }
#else
    xsink->raiseException("PROCESS-TERMINATE-UNSUPPORTED-ERROR", "this call is not supported on this platform");
#endif
}

void ProcessPriv::waitForTermination(int pid, ExceptionSink* xsink) {
#ifdef HAVE_KILL
    while (true) {
        if (kill(pid, 0)) {
            break;
        }
        usleep(WAIT_POLL_US);
    }
#else
    xsink->raiseException("PROCESS-WAITFORTERMINATION-UNSUPPORTED-ERROR", "this call is not supported on this "
        "platform");
#endif
}

#if defined(__linux__)
#include <sys/stat.h>

int64 ProcessPriv::getDescriptorCount(ExceptionSink* xsink, int pid) {
    // NOTE from https://docs.kernel.org/filesystems/proc.html
    // "The number of open files for the process is stored in ‘size’ member of stat() output for /proc/<pid>/fd for
    // fast access"
    QoreStringMaker dir("/proc/%d/fd", pid);
    struct stat statbuf;
    int rc = stat(dir.c_str(), &statbuf);
    if (rc < 0) {
        xsink->raiseErrnoException("PROCESS-GETDESCRIPTORCOUNT-ERROR", errno, "could not read file descriptor count "
            "for PID %d", pid);
        return -1;
    }
    return statbuf.st_size;
}
#endif

#if defined(__APPLE__) && defined(__MACH__)
#include <libproc.h>

int64 ProcessPriv::getDescriptorCount(ExceptionSink* xsink, int pid) {
    int count;
    while (true) {
        int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (bufsize <= 0) {
            xsink->raiseErrnoException("PROCESS-GETDESCRIPTORCOUNT-ERROR", errno, "could not read file descriptor "
                "count for PID %d", pid);
            return -1;
        }
        // we have the max allocated size, now we need to find the actual number of descriptors by making a real call
        void* buf = malloc(bufsize);
        if (!buf) {
            xsink->raiseException("PROCESS-GETDESCRIPTORCOUNT-ERROR", "could not allocate memory for file descriptor "
                "buffer for PID %d", pid);
            return -1;
        }
        ON_BLOCK_EXIT(free, buf);
        count = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf, bufsize);
        if (count <= 0) {
            xsink->raiseErrnoException("PROCESS-GETDESCRIPTORCOUNT-ERROR", errno, "could not read file descriptor "
                "count for PID %d", pid);
            return -1;
        }
        if (count > bufsize) {
            printd(0, "ProcessPriv::getDescriptorCount() count %d > bufsize %d for PID %d; retrying\n", count,
                bufsize, pid);
            continue;
        }
        break;
    }

    return count / sizeof(proc_fdinfo);
}
#endif

#if !defined(__linux__) && (!defined(__APPLE__) || !defined(__MACH__))
int64 ProcessPriv::getDescriptorCount(ExceptionSink* xsink, int pid) {
    xsink->raiseException("PROCESS-GETDESCRIPTORCOUNT-UNSUPPORTED-ERROR", "this call is not supported on this "
        "platform");
    return -1;
}
#endif

#include <sys/resource.h>

static QoreHashNode* rusageToHash(const struct rusage& ru, ExceptionSink* xsink) {
    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(autoTypeInfo), xsink);

    // Convert timeval to float seconds
    double user_time = ru.ru_utime.tv_sec + (ru.ru_utime.tv_usec / 1000000.0);
    double system_time = ru.ru_stime.tv_sec + (ru.ru_stime.tv_usec / 1000000.0);

    rv->setKeyValue("user_time", user_time, xsink);
    rv->setKeyValue("system_time", system_time, xsink);

    // On Linux, ru_maxrss is in kilobytes; on macOS it's in bytes
#if defined(__APPLE__) && defined(__MACH__)
    rv->setKeyValue("max_rss", (int64)ru.ru_maxrss, xsink);
#else
    rv->setKeyValue("max_rss", (int64)ru.ru_maxrss * 1024, xsink);
#endif

    rv->setKeyValue("shared_size", (int64)ru.ru_ixrss, xsink);
    rv->setKeyValue("unshared_data_size", (int64)ru.ru_idrss, xsink);
    rv->setKeyValue("unshared_stack_size", (int64)ru.ru_isrss, xsink);
    rv->setKeyValue("minor_faults", (int64)ru.ru_minflt, xsink);
    rv->setKeyValue("major_faults", (int64)ru.ru_majflt, xsink);
    rv->setKeyValue("swaps", (int64)ru.ru_nswap, xsink);
    rv->setKeyValue("block_input", (int64)ru.ru_inblock, xsink);
    rv->setKeyValue("block_output", (int64)ru.ru_oublock, xsink);
    rv->setKeyValue("messages_sent", (int64)ru.ru_msgsnd, xsink);
    rv->setKeyValue("messages_received", (int64)ru.ru_msgrcv, xsink);
    rv->setKeyValue("signals_received", (int64)ru.ru_nsignals, xsink);
    rv->setKeyValue("voluntary_context_switches", (int64)ru.ru_nvcsw, xsink);
    rv->setKeyValue("involuntary_context_switches", (int64)ru.ru_nivcsw, xsink);

    return rv.release();
}

QoreHashNode* ProcessPriv::getResourceUsage(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return nullptr;
    }

    // For child processes, use RUSAGE_CHILDREN
    struct rusage ru;
    if (getrusage(RUSAGE_CHILDREN, &ru) == -1) {
        xsink->raiseErrnoException("PROCESS-GETRESOURCEUSAGE-ERROR", errno, "getrusage() failed");
        return nullptr;
    }

    return rusageToHash(ru, xsink);
}

QoreHashNode* ProcessPriv::getResourceUsage(int pid, ExceptionSink* xsink) {
    // For a specific PID, we can only get resource usage if:
    // 1. It's the current process (use RUSAGE_SELF)
    // 2. It's our child (use RUSAGE_CHILDREN)
    // 3. On Linux, we can read /proc/PID/stat

    if (pid == getpid()) {
        struct rusage ru;
        if (getrusage(RUSAGE_SELF, &ru) == -1) {
            xsink->raiseErrnoException("PROCESS-GETRESOURCEUSAGE-ERROR", errno, "getrusage() failed");
            return nullptr;
        }
        return rusageToHash(ru, xsink);
    }

#ifdef __linux__
    // On Linux, we can read from /proc/PID/stat
    QoreStringMaker path("/proc/%d/stat", pid);
    QoreFile f;
    if (f.open(path.c_str())) {
        xsink->raiseException("PROCESS-GETRESOURCEUSAGE-ERROR", "cannot open %s: %s", path.c_str(), strerror(errno));
        return nullptr;
    }

    QoreStringNodeHolder content(f.read(-1, -1, xsink));
    if (*xsink) {
        return nullptr;
    }

    // Parse /proc/PID/stat - fields are space-separated
    // We need: utime (14), stime (15), vsize (23), rss (24), minflt (10), majflt (12)
    // Field numbering starts at 1
    const char* p = content->c_str();

    // Skip past the command name (in parentheses) since it may contain spaces
    const char* start = strchr(p, '(');
    const char* end = strrchr(p, ')');
    if (!start || !end) {
        xsink->raiseException("PROCESS-GETRESOURCEUSAGE-ERROR", "cannot parse /proc/%d/stat", pid);
        return nullptr;
    }
    p = end + 2;  // Skip ") "

    // Parse remaining fields (starting at field 3)
    int64 utime = 0, stime = 0, minflt = 0, majflt = 0, vsize = 0, rss = 0;
    int field = 3;
    while (*p) {
        // Skip whitespace
        while (*p == ' ') p++;
        if (!*p) break;

        // Read field value
        char* endptr;
        long long val = strtoll(p, &endptr, 10);

        switch (field) {
            case 10: minflt = val; break;  // minflt
            case 12: majflt = val; break;  // majflt
            case 14: utime = val; break;   // utime (clock ticks)
            case 15: stime = val; break;   // stime (clock ticks)
            case 23: vsize = val; break;   // vsize
            case 24: rss = val; break;     // rss (pages)
        }

        // Move to next field
        p = endptr;
        field++;
        if (field > 24) break;
    }

    // Convert clock ticks to seconds
    long ticks_per_sec = sysconf(_SC_CLK_TCK);
    long page_size = sysconf(_SC_PAGESIZE);

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(autoTypeInfo), xsink);
    rv->setKeyValue("user_time", (double)utime / ticks_per_sec, xsink);
    rv->setKeyValue("system_time", (double)stime / ticks_per_sec, xsink);
    rv->setKeyValue("max_rss", rss * page_size, xsink);
    rv->setKeyValue("shared_size", (int64)0, xsink);
    rv->setKeyValue("unshared_data_size", (int64)0, xsink);
    rv->setKeyValue("unshared_stack_size", (int64)0, xsink);
    rv->setKeyValue("minor_faults", minflt, xsink);
    rv->setKeyValue("major_faults", majflt, xsink);
    rv->setKeyValue("swaps", (int64)0, xsink);
    rv->setKeyValue("block_input", (int64)0, xsink);
    rv->setKeyValue("block_output", (int64)0, xsink);
    rv->setKeyValue("messages_sent", (int64)0, xsink);
    rv->setKeyValue("messages_received", (int64)0, xsink);
    rv->setKeyValue("signals_received", (int64)0, xsink);
    rv->setKeyValue("voluntary_context_switches", (int64)0, xsink);
    rv->setKeyValue("involuntary_context_switches", (int64)0, xsink);

    return rv.release();
#else
    xsink->raiseException("PROCESS-GETRESOURCEUSAGE-UNSUPPORTED-ERROR",
        "getting resource usage for arbitrary PIDs is only supported on Linux");
    return nullptr;
#endif
}

QoreListNode* ProcessPriv::getChildPids(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return nullptr;
    }

    int pid = detached_pid ? detached_pid : m_process->id();
    return getChildPids(pid, xsink);
}

QoreListNode* ProcessPriv::getChildPids(int pid, ExceptionSink* xsink) {
    // Safety check: never allow getting children of PID 1 (init) or invalid PIDs
    // This prevents accidentally killing system processes
    if (pid <= 1) {
        xsink->raiseException("PROCESS-GETCHILDPIDS-ERROR",
            "refusing to get children of PID %d (must be > 1)", pid);
        return nullptr;
    }

#ifdef __linux__
    // On Linux, read /proc/PID/task/PID/children if available (kernel 3.5+)
    // or parse all /proc/*/stat files looking for parent PID
    QoreStringMaker childrenPath("/proc/%d/task/%d/children", pid, pid);
    QoreFile f;

    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    if (f.open(childrenPath.c_str()) == 0) {
        // Modern kernel with /proc/PID/task/PID/children support
        QoreStringNodeHolder content(f.read(-1, -1, xsink));
        if (*xsink) {
            return nullptr;
        }

        // Handle empty file (process has no children) or nullptr
        if (!content || !content->size()) {
            return rv.release();
        }

        const char* p = content->c_str();
        while (*p) {
            // Skip whitespace
            while (*p == ' ' || *p == '\t' || *p == '\n') p++;
            if (!*p) break;

            // Read PID
            char* endptr;
            long childPid = strtol(p, &endptr, 10);
            if (endptr > p) {
                rv->push(childPid, xsink);
            }
            p = endptr;
        }
    } else {
        // Fallback: scan all /proc/*/stat files
        DIR* procdir = opendir("/proc");
        if (!procdir) {
            xsink->raiseErrnoException("PROCESS-GETCHILDPIDS-ERROR", errno, "cannot open /proc");
            return nullptr;
        }

        struct dirent* entry;
        while ((entry = readdir(procdir)) != nullptr) {
            // Check if entry is a number (PID)
            char* endptr;
            long entryPid = strtol(entry->d_name, &endptr, 10);
            if (*endptr != '\0' || entryPid <= 0) {
                continue;
            }

            // Read /proc/PID/stat
            QoreStringMaker statPath("/proc/%ld/stat", entryPid);
            QoreFile statFile;
            if (statFile.open(statPath.c_str()) != 0) {
                continue;
            }

            QoreStringNodeHolder statContent(statFile.read(-1, -1, xsink));
            if (*xsink) {
                xsink->clear();  // Ignore errors reading individual stat files
                continue;
            }

            // Safety check for null or empty content
            if (!statContent || !statContent->size()) {
                continue;
            }

            // Parse stat file to get PPID (field 4)
            const char* p = statContent->c_str();
            const char* end = strrchr(p, ')');
            if (!end) continue;
            p = end + 2;  // Skip ") "

            // Skip state (field 3)
            while (*p == ' ') p++;
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;

            // Read PPID (field 4)
            long ppid = strtol(p, &endptr, 10);
            if (ppid == pid) {
                rv->push(entryPid, xsink);
            }
        }
        closedir(procdir);
    }

    return rv.release();
#elif defined(__APPLE__) && defined(__MACH__)
    // On macOS, use libproc to get child PIDs
    ReferenceHolder<QoreListNode> rv(new QoreListNode(bigIntTypeInfo), xsink);

    // Get list of all PIDs
    int numPids = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (numPids <= 0) {
        return rv.release();  // Return empty list
    }

    std::vector<pid_t> pids(numPids);
    numPids = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), numPids * sizeof(pid_t));
    numPids /= sizeof(pid_t);

    for (int i = 0; i < numPids; i++) {
        struct proc_bsdinfo info;
        int size = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (size == sizeof(info) && info.pbi_ppid == pid) {
            rv->push((int64)pids[i], xsink);
        }
    }

    return rv.release();
#else
    xsink->raiseException("PROCESS-GETCHILDPIDS-UNSUPPORTED-ERROR",
        "getting child PIDs is not supported on this platform");
    return nullptr;
#endif
}

bool ProcessPriv::terminateTree(ExceptionSink* xsink) {
    if (!processCheck(xsink)) {
        return false;
    }

    // TEMPORARILY DISABLED: Child process killing is disabled due to a bug that causes
    // incorrect PIDs to be killed. For now, just terminate the main process.
    // TODO: Fix the getChildPids implementation and re-enable child killing.
    //
    // The issue is that getChildPids or the PPID verification is somehow returning
    // or approving incorrect PIDs, leading to killing unrelated processes like
    // systemd, ssh sessions, etc.

    // Just terminate the main process for now
    return terminate(xsink);
}

QoreHashNode* ProcessPriv::run(const char* command, const QoreListNode* arguments,
        const QoreHashNode* opts, int64 timeout_ms, ExceptionSink* xsink) {
    // Create process
    ReferenceHolder<ProcessPriv> proc(new ProcessPriv(command, arguments, opts, xsink), xsink);
    if (*xsink) {
        return nullptr;
    }

    // Wait for completion
    bool finished;
    if (timeout_ms > 0) {
        finished = proc->wait(timeout_ms, xsink);
    } else {
        finished = proc->wait(xsink);
    }

    if (*xsink) {
        return nullptr;
    }

    // Collect stdout
    SimpleRefHolder<QoreStringNode> stdout_str(new QoreStringNode);
    while (true) {
        QoreStringNode* chunk = proc->readStdout(4096, xsink);
        if (*xsink) {
            return nullptr;
        }
        if (!chunk) {
            break;
        }
        stdout_str->concat(chunk);
        chunk->deref();
    }

    // Collect stderr
    SimpleRefHolder<QoreStringNode> stderr_str(new QoreStringNode);
    while (true) {
        QoreStringNode* chunk = proc->readStderr(4096, xsink);
        if (*xsink) {
            return nullptr;
        }
        if (!chunk) {
            break;
        }
        stderr_str->concat(chunk);
        chunk->deref();
    }

    // Build result hash
    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(autoTypeInfo), xsink);
    rv->setKeyValue("stdout", stdout_str.release(), xsink);
    rv->setKeyValue("stderr", stderr_str.release(), xsink);
    rv->setKeyValue("exit_code", proc->exitCode(xsink), xsink);
    rv->setKeyValue("ok", finished, xsink);

    // If process didn't finish (timeout), terminate it
    if (!finished) {
        proc->terminate(xsink);
    }

    return rv.release();
}
