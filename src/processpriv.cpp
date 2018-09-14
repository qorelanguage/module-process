#include <iostream>
#include <cstddef>
#include <boost/numeric/conversion/cast.hpp>

#include "processpriv.h"
#include "qoreprocesshandler.h"
#include "unix-config.h"

namespace bp = boost::process;
namespace ex = boost::process::extend;

DLLLOCAL extern const TypedHashDecl* hashdeclMemorySummaryInfo;

#define PROCESS_CHECK(RET) if (!m_process) { xsink->raiseException("PROCESS-CHECK-ERROR", "Process is not initialized"); return (RET); }


ProcessPriv::ProcessPriv()
    : m_process(0),
      m_asio_svc(),
      m_in(m_asio_svc), m_out(m_asio_svc), m_err(m_asio_svc)
{
	// TODO: how async completion handlers can work here with Qore exceptions?
//    boost::asio::async_read(m_asio_svc, m_out_buff);
//    boost::asio::async_read(m_asio_svc, m_err_buff);
}

ProcessPriv::ProcessPriv(pid_t pid, ExceptionSink *xsink)
    : ProcessPriv()
{
    try {
        int i = boost::numeric_cast<int>(pid);
        m_process = new bp::child(i);
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-CONSTRUCTOR-ERROR", ex.what());
    }
}

ProcessPriv::ProcessPriv(const char* command, const QoreListNode* arguments, const QoreHashNode *opts, ExceptionSink *xsink)
    : ProcessPriv()
{
    const ResolvedCallReferenceNode* on_success = optsExecutor("on_success", opts, xsink);
    const ResolvedCallReferenceNode* on_setup = optsExecutor("on_setup", opts, xsink);
    const ResolvedCallReferenceNode* on_error = optsExecutor("on_error", opts, xsink);
    const ResolvedCallReferenceNode* on_fork_error = optsExecutor("on_fork_error", opts, xsink);
    const ResolvedCallReferenceNode* on_exec_setup = optsExecutor("on_exec_setup", opts, xsink);
    const ResolvedCallReferenceNode* on_exec_error = optsExecutor("on_exec_error", opts, xsink);

    bp::environment e = optsEnv(opts, xsink);
    boost::filesystem::path p = optsPath(command, opts, xsink);

    const char* cwd = optsCwd(opts, xsink);

    if (xsink->isException()) {
        return;
    }

    std::vector<std::string> a;
    if (arguments) {
        //std::cout << "size: " << arguments->size() << std::endl;
        for (qore_size_t i = 0; i < arguments->size(); i++) {
            QoreStringNodeValueHelper s(arguments->retrieveEntry(i));
            //std::cout << "arg=" << s->getBuffer() << std::endl;
            a.push_back(s->getBuffer());
        }
    }
    else {
        a.push_back(""); // just a dummy argument to get it working inside child()
    }

    try {
        m_process = new bp::child(bp::exe = p.string(),
                                  bp::args = a,
                                  bp::env = e,
                                  bp::start_dir = cwd,
                                  QoreProcessHandler(xsink,
                                                     on_success,
                                                     on_setup,
                                                     on_error,
                                                     on_fork_error,
                                                     on_exec_setup,
                                                     on_exec_error
                                                    ),
                                  bp::std_out > m_out,
                                  bp::std_err > m_err,
                                  bp::std_in < m_in,
				  m_asio_svc
                                 );
	m_asio_svc.run();
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-CONSTRUCTOR-ERROR", ex.what());
    }
}

ProcessPriv::~ProcessPriv() {
    if (m_process)
        delete m_process;
    m_process = 0;
}

const ResolvedCallReferenceNode* ProcessPriv::optsExecutor(const char* name, const QoreHashNode* oh, ExceptionSink *xsink)
{
    const ResolvedCallReferenceNode* ret = nullptr;

    if (oh) {
        if (oh->existsKey(name)) {
            QoreValue n = oh->getKeyValue(name);
            if (n.getType() != NT_RUNTIME_CLOSURE && n.getType() != NT_FUNCREF)
            {
                xsink->raiseException("PROCESS-OPTIONS-ERROR",
                                      "executor '%s' required code as value, got: '%s'(%d)",
                                      name,
                                      n.getTypeName(),
                                      n.getType()
                                     );
                return ret;
            }

            // TODO/FIXME: should I increase ref count here?
            ret = n.get<const ResolvedCallReferenceNode>();
        }
    }

    return ret;
}

bp::environment ProcessPriv::optsEnv(const QoreHashNode *opts, ExceptionSink *xsink)
{
    // as agreed - we are not merging current process env. We are replacing.
    // The "merge" can be done with global ENV hash
    // bp::environment ret = boost::this_process::environment();
    bp::environment ret;

    if (opts && opts->existsKey("env")) {
        QoreValue n = opts->getKeyValue("env");
        if (n.getType() != NT_HASH)
        {
            xsink->raiseException("PROCESS-OPTIONS-ERROR",
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
    }
    else
        return boost::this_process::environment();
}

const char* ProcessPriv::optsCwd(const QoreHashNode *opts, ExceptionSink *xsink)
{
    const char * ret = ".";

    if (opts && opts->existsKey("cwd")) {
        QoreValue n = opts->getKeyValue("cwd");
        if (n.getType() != NT_STRING)
        {
            xsink->raiseException("PROCESS-OPTIONS-ERROR",
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

boost::filesystem::path ProcessPriv::optsPath(const char* command, const QoreHashNode *opts, ExceptionSink *xsink)
{
    boost::filesystem::path ret;

    if (opts && opts->existsKey("path")) {
        QoreValue n = opts->getKeyValue("path");
        if (n.getType() != NT_LIST) {
            xsink->raiseException("PROCESS-OPTIONS-ERROR",
                                  "Path option must be a list of strings, got: '%s'(%d)",
                                  n.getTypeName(),
                                  n.getType()
                                 );
            return ret;
        }

        const QoreListNode *l = n.get<const QoreListNode>();
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

    if (ret.empty()) {
        // issue #2524 if the command is already absolute, then use it
        ret = command;
        if (ret.is_absolute())
            return ret;

        ret.clear();
        xsink->raiseException("PROCESS-SEARCH-PATH-ERROR", "Command '%s' cannot be found in PATH", command);
    }
    return boost::filesystem::absolute(ret);
}

int ProcessPriv::exitCode(ExceptionSink *xsink) {
    PROCESS_CHECK(-1)

    try {
        return m_process->exit_code();
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-EXITCODE-ERROR", ex.what());
    }

    return -1;
}

int ProcessPriv::id(ExceptionSink *xsink) {
    PROCESS_CHECK(-1)

    try {
        return m_process->id();
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-ID-ERROR", ex.what());
    }

    return -1;
}

bool ProcessPriv::valid(ExceptionSink *xsink) {
    PROCESS_CHECK(false)

    try {
        return m_process->valid();
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-VALID-ERROR", ex.what());
    }

    return false;
}

bool ProcessPriv::running(ExceptionSink *xsink) {
    PROCESS_CHECK(false)

    try {
        return m_process->running();
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-RUNNING-ERROR", ex.what());
    }

    return false;
}

bool ProcessPriv::wait(ExceptionSink *xsink) {
    PROCESS_CHECK(false)

    try {
        if (m_process->valid()) {
//            m_asio_svc.run();
            m_process->wait();
//            TODO: exceptions + completion handler?
        }
        return true;
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-WAIT-ERROR", ex.what());
    }

    return false;
}

bool ProcessPriv::wait(int64 t, ExceptionSink *xsink)
{
    PROCESS_CHECK(false)

    try {
        if (m_process->valid() && m_process->running()) {
//            m_asio_svc.run();
            return m_process->wait_for(std::chrono::milliseconds(t));
        }
        return false;
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-WAIT-ERROR", ex.what());
    }

    return false;
}

bool ProcessPriv::detach(ExceptionSink *xsink)
{
    PROCESS_CHECK(false);
    m_process->detach();
    return true;
}

QoreStringNode* ProcessPriv::readStderr()
{
	// TODO: asio reimplementation + exception handling
//    std::string line;
//    std::getline(m_err, line);
//    return new QoreStringNode(line);
return 0;
}

QoreStringNode* ProcessPriv::readStderr(std::streamsize size, ExceptionSink* xsink)
{
    std::string buff(size, '\0');

    try {
//        m_err.read(&buff[0], size);
throw std::runtime_error("TODO: reimplement asio");
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    // we must let Qore calculate the string's length; the std::string object thinks it's "size" bytes long
    return new QoreStringNode(buff.c_str());
}

QoreStringNode* ProcessPriv::readStdout()
{
	// TODO: asio reimplementation + exception handling
//    std::string line;
//    std::getline(m_out, line);
//    return new QoreStringNode(line);
return 0;
}

QoreStringNode* ProcessPriv::readStdout(std::streamsize size, ExceptionSink* xsink)
{
    std::string buff(size, '\0');

    try {
//        m_out.read(&buff[0], size);
        throw std::runtime_error("TODO: asio migration");
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    // we must let Qore calculate the string's length; the std::string object thinks it's "size" bytes long
    return new QoreStringNode(buff.c_str());
}

void ProcessPriv::write(std::string val, ExceptionSink *xsink)
{
    try {
        //m_in.write(val.data(), val.size());
        //m_in.flush();
        m_in.write_some(boost::asio::buffer(val, val.size()));// TODO: examine how to handle exceptions as it is async now. It should have some completion handled probably
    }
    catch (const std::invalid_argument& e) {
        xsink->raiseException("PROCESS-WRITE-EXCEPTION", e.what());
    }
}

bool ProcessPriv::terminate(ExceptionSink *xsink) {
    PROCESS_CHECK(false)

    try {
        m_process->terminate();
        return true;
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-TERMINATE-ERROR", ex.what());
    }

    return false;
}

#ifdef __linux__
#include <string.h>
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
        rss = strtoll(l.c_str() + pos + 1, nullptr, 10) * PAGE_SIZE;
        l.terminate(pos);
        vsz = l.toBigInt() * PAGE_SIZE;
    }

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclMemorySummaryInfo, xsink), xsink);

    rv->setKeyValue("vsz", vsz, xsink);
    rv->setKeyValue("rss", rss, xsink);

    {
        QoreStringMaker str("/proc/%d/maps", pid);
        if (f.open(str.c_str())) {
            xsink->raiseErrnoException("PROCESS-GETMEMORYINFO-ERROR", errno, "could not read virtual memory map for PID %d", pid);
            return nullptr;
        }
    }

    int64 priv_size = 0;

    while (true) {
        if (f.readLine(l))
            break;

        // maps line format: 0=start-end 1=perms 2=offset 3=device 4=inode 5=pathname
        // ex: 01f1c000-01f3d000 rw-p 00000000 00:00 0                                  [heap]

        // find memory range separator
        qore_offset_t pos = l.find('-');
        assert(pos != -1);

        // find end of memory range
        qore_offset_t pos1 = l.find(' ', pos + 1);
        assert(pos1 != -1);

        // if memory is not writable or private then skip
        if (l[pos1 + 2] != 'w' || l[pos1 + 4] != 'p')
            continue;

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
        assert(pos1 != -1);
        {
            QoreString num(l.c_str() + pos, pos1 - pos);
            // skip mmap()'ed entries with a non-zero inode value
            if (num.toBigInt())
                continue;
        }

        priv_size += (end - start);
        //printd(5, "end: %lx start: %lx ps: %lld\n", end, start, priv_size);
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
