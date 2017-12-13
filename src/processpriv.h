#ifndef PROCESSPRIV_H
#define PROCESSPRIV_H

#include <qore/Qore.h>
#include <boost/process.hpp>

#include <unistd.h>

DLLLOCAL extern qore_classid_t CID_PROCESS;
DLLLOCAL extern QoreClass* QC_PROCESS;

namespace bp = boost::process;


class ProcessPriv : public AbstractPrivateData {
protected:
    DLLLOCAL virtual ~ProcessPriv();

public:
    DLLLOCAL ProcessPriv(pid_t pid, ExceptionSink *xsink);

    DLLLOCAL ProcessPriv(const char* command, const QoreListNode* arguments, const QoreHashNode *opts, ExceptionSink *xsink);

    DLLLOCAL int exitCode(ExceptionSink *xsink);

    DLLLOCAL int id(ExceptionSink *xsink);

    DLLLOCAL bool valid(ExceptionSink *xsink);

    DLLLOCAL bool running(ExceptionSink *xsink);

    DLLLOCAL bool wait(ExceptionSink *xsink);

    DLLLOCAL bool wait(int64 t, ExceptionSink *xsink);

    DLLLOCAL bool detach(ExceptionSink *xsink);

    DLLLOCAL bool terminate(ExceptionSink *xsink);

    DLLLOCAL void write(std::string val, ExceptionSink *xsink);

    DLLLOCAL QoreStringNode* readStderr();
    DLLLOCAL QoreStringNode* readStderr(std::streamsize size, ExceptionSink* xsink);

    DLLLOCAL QoreStringNode* readStdout();
    DLLLOCAL QoreStringNode* readStdout(std::streamsize size, ExceptionSink* xsink);

    DLLLOCAL static boost::filesystem::path optsPath(const char* command, const QoreHashNode *opts, ExceptionSink *xsink);

    DLLLOCAL static QoreHashNode* getMemoryInfo(int pid, ExceptionSink* xsink);

private:
    bp::child *m_process;
    bp::opstream m_in;
    bp::ipstream m_out;
    bp::ipstream m_err;

    const ResolvedCallReferenceNode* optsExecutor(const char * name, const QoreHashNode *opts, ExceptionSink *xsink);

    bp::environment optsEnv(const QoreHashNode *opts, ExceptionSink *xsink);
    const char* optsCwd(const QoreHashNode *opts, ExceptionSink *xsink);
};

#endif
