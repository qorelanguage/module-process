#ifndef QOREPROCESSHANDLER_H
#define QOREPROCESSHANDLER_H

#include <qore/Qore.h>
#include <boost/process/extend.hpp>


namespace bp = boost::process;
namespace ex = boost::process::extend;


class QoreProcessHandler : public ex::handler {

private:
    ExceptionSink *m_xsink;
    const ResolvedCallReferenceNode *m_on_success;
    const ResolvedCallReferenceNode *m_on_setup;
    const ResolvedCallReferenceNode *m_on_error;
    const ResolvedCallReferenceNode *m_on_fork_error;
    const ResolvedCallReferenceNode *m_on_exec_setup;
    const ResolvedCallReferenceNode *m_on_exec_error;

public:

    QoreProcessHandler(
        ExceptionSink *xsink,
        const ResolvedCallReferenceNode *on_success,
        const ResolvedCallReferenceNode *on_setup,
        const ResolvedCallReferenceNode *on_error,
        const ResolvedCallReferenceNode *on_fork_error,
        const ResolvedCallReferenceNode *on_exec_setup,
        const ResolvedCallReferenceNode *on_exec_error
    ) : m_xsink(xsink),
        m_on_success(on_success),
        m_on_setup(on_setup),
        m_on_error(on_error),
        m_on_fork_error(on_fork_error),
        m_on_exec_setup(on_exec_setup),
        m_on_exec_error(on_exec_error)
    {
    }

    template<typename Executor>
    void on_success(Executor & exec) const {
        call("on_success", m_on_success, exec, std::error_code());
    }

    template<typename Executor>
    void on_setup(Executor & exec) const {
        call("on_setup", m_on_setup, exec, std::error_code());
    }

    template<typename Executor>
    void on_error(Executor & exec, const std::error_code &ec) const {
        call("on_error", m_on_error, exec, ec);
    }

    template<typename Executor>
    void on_fork_error(Executor & exec, const std::error_code & ec) const {
        call("on_fork_error", m_on_fork_error, exec, ec);
    }

    template<typename Executor>
    void on_exec_setup(Executor & exec) const {
        call("on_exec_setup", m_on_exec_setup, exec, std::error_code());
    }

    template<typename Executor>
    void on_exec_error(Executor & exec, const std::error_code &ec) const {
        call("on_exec_error", m_on_exec_error, exec, ec);
    }

    template<typename Executor>
    void call(const char* info,
              const ResolvedCallReferenceNode *callref,
              Executor & exec,
              const std::error_code &ec
              ) const
    {
        if (!callref) {
            //std::cout << "    info: " << info << ": no handler installed" << std::endl;
            return;
        }

        QoreHashNode *e = new QoreHashNode(autoTypeInfo);
        e->setKeyValue("name", new QoreStringNode(info), m_xsink);
        e->setKeyValue("exe", new QoreStringNode(exec.exe), m_xsink);
#ifndef WINDOWS_API
        e->setKeyValue("pid", exec.pid, m_xsink);
#else
        e->setKeyValue("pid", exec.proc_info.dwProcessId, m_xsink);
#endif
        e->setKeyValue("exit", (int64)*(exec.exit_status), m_xsink);
        // std::error_code &ec to hash too
        e->setKeyValue("error_code", ec.value(), m_xsink);
        e->setKeyValue("error_message", new QoreStringNode(ec.message()), m_xsink);
        e->setKeyValue("error_category", new QoreStringNode(ec.category().name()), m_xsink);

        ReferenceHolder<QoreListNode> args(new QoreListNode(autoTypeInfo), m_xsink);
        args->push(e, m_xsink);
        callref->execValue(*args, m_xsink);
    }

};

#endif
