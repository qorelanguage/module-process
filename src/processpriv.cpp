#include <iostream>
#include <cstddef>
#include <boost/numeric/conversion/cast.hpp>

#include "processpriv.h"
#include "qoreprocesshandler.h"

namespace bp = boost::process;
namespace ex = boost::process::extend;


#define PROCESS_CHECK(RET) if (!m_process) { xsink->raiseException("PROCESS-CHECK-ERROR", "Process is not initialized"); return (RET); }


ProcessPriv::ProcessPriv(pid_t pid, ExceptionSink *xsink)
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
    : m_process(0)
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
            QoreStringNodeValueHelper s(arguments->retrieve_entry(i));
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
                                  bp::std_in < m_in
                                 );
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

const ResolvedCallReferenceNode* ProcessPriv::optsExecutor(const char * name, const QoreHashNode *opts, ExceptionSink *xsink)
{
    const ResolvedCallReferenceNode* ret = 0;

    if (opts) {
        const QoreHashNode *oh = reinterpret_cast<const QoreHashNode*>(opts);
        if (oh->existsKey(name)) {
            const AbstractQoreNode *n = oh->getKeyValue(name);
            if (n->getType() != NT_RUNTIME_CLOSURE && n->getType() != NT_FUNCREF)
            {
                xsink->raiseException("PROCESS-OPTIONS-ERROR",
                                      "executor '%s' required code as value, got: '%s'(%d)",
                                      name,
                                      n->getTypeName(),
                                      n->getType()
                                     );
                return ret;
            }

            // TODO/FIXME: should I increase ref count here?
            ret = reinterpret_cast<const ResolvedCallReferenceNode*>(n);
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
        const AbstractQoreNode *n = opts->getKeyValue("env");
        if (n->getType() != NT_HASH)
        {
            xsink->raiseException("PROCESS-OPTIONS-ERROR",
                                  "Environment variables option must be a hash, got: '%s'(%d)",
                                  n->getTypeName(),
                                  n->getType()
                                 );
            return ret;
        }

        ConstHashIterator it(reinterpret_cast<const QoreHashNode*>(n));
        while (it.next()) {
            QoreStringValueHelper val(it.getValue());
            ret[it.getKey()] = val->getBuffer();
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
        const AbstractQoreNode *n = opts->getKeyValue("cwd");
        if (n->getType() != NT_STRING)
        {
            xsink->raiseException("PROCESS-OPTIONS-ERROR",
                                  "Working dir 'cwd' option must be a string, got: '%s'(%d)",
                                  n->getTypeName(),
                                  n->getType()
                                 );
            return ret;
        }
        QoreStringValueHelper s(n);
        ret = s->getBuffer();
    }

    return ret;
}

boost::filesystem::path ProcessPriv::optsPath(const char* command, const QoreHashNode *opts, ExceptionSink *xsink)
{
    boost::filesystem::path ret;

    if (opts && opts->existsKey("path")) {
        const AbstractQoreNode *n = opts->getKeyValue("path");
        if (n->getType() != NT_LIST) {
            xsink->raiseException("PROCESS-OPTIONS-ERROR",
                                  "Path option must be a list of strings, got: '%s'(%d)",
                                  n->getTypeName(),
                                  n->getType()
                                 );
            return ret;
        }

        const QoreListNode *l = reinterpret_cast<const QoreListNode *>(n);
        std::vector<boost::filesystem::path> paths;

        for (qore_size_t i = 0; i < l->size(); i++) {
            QoreStringValueHelper s(l->retrieve_entry(i));
            paths.push_back(boost::filesystem::path(s->getBuffer()));
        }

        ret = bp::search_path(command, paths);
    }
    else {
        ret = bp::search_path(command);
    }

    if (ret.empty()) {
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
        if (m_process->valid())
            m_process->wait();
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
        if (m_process->valid() && m_process->running())
            return m_process->wait_for(std::chrono::milliseconds(t));
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
    std::string line;
    std::getline(m_err, line);
    return new QoreStringNode(line);
}

QoreStringNode* ProcessPriv::readStderr(std::streamsize size, ExceptionSink* xsink)
{
    std::string buff(size, '\0');

    try {
        m_err.read(&buff[0], size);
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return new QoreStringNode(buff);
}

QoreStringNode* ProcessPriv::readStdout()
{
    std::string line;
    std::getline(m_out, line);
    return new QoreStringNode(line);
}

QoreStringNode* ProcessPriv::readStdout(std::streamsize size, ExceptionSink* xsink)
{
    std::string buff(size, '\0');

    try {
        m_out.read(&buff[0], size);
    }
    catch (const std::exception &ex) {
        xsink->raiseException("PROCESS-READ-ERROR", ex.what());
    }

    return new QoreStringNode(buff);
}

void ProcessPriv::write(std::string val, ExceptionSink *xsink)
{
    try {
        m_in.write(val.data(), val.size());
        m_in.flush();
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
