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

#ifndef QOREPROCESSHANDLER_H
#define QOREPROCESSHANDLER_H

#include <boost/process.hpp>
#include <boost/process/extend.hpp>

#include <qore/Qore.h>

namespace bp = boost::process;
namespace ex = boost::process::extend;

class QoreProcessHandler : public ex::async_handler {
public:
    DLLLOCAL QoreProcessHandler(ExceptionSink* xsink,
            ResolvedCallReferenceNode* on_success,
            ResolvedCallReferenceNode* on_setup,
            ResolvedCallReferenceNode* on_error,
            ResolvedCallReferenceNode* on_fork_error,
            ResolvedCallReferenceNode* on_exec_setup,
            ResolvedCallReferenceNode* on_exec_error,
            int& exit_code) :
        m_xsink(xsink),
        m_on_success(on_success, xsink),
        m_on_setup(on_setup, xsink),
        m_on_error(on_error, xsink),
        m_on_fork_error(on_fork_error, xsink),
        m_on_exec_setup(on_exec_setup, xsink),
        m_on_exec_error(on_exec_error, xsink),
        exit_code(exit_code) {
    }

    QoreProcessHandler(QoreProcessHandler& old) = delete;

    template<typename Executor>
    DLLLOCAL void on_success(Executor& exec) const {
        call("on_success", *m_on_success, exec, std::error_code());
    }

    template<typename Executor>
    DLLLOCAL void on_setup(Executor& exec) const {
        call("on_setup", *m_on_setup, exec, std::error_code());
    }

    template<typename Executor>
    DLLLOCAL void on_error(Executor& exec, const std::error_code& ec) const {
        call("on_error", *m_on_error, exec, ec);
    }

    template<typename Executor>
    DLLLOCAL void on_fork_error(Executor& exec, const std::error_code& ec) const {
        call("on_fork_error", *m_on_fork_error, exec, ec);
    }

    template<typename Executor>
    DLLLOCAL void on_exec_setup(Executor& exec) const {
        call("on_exec_setup", *m_on_exec_setup, exec, std::error_code());
    }

    template<typename Executor>
    DLLLOCAL void on_exec_error(Executor& exec, const std::error_code& ec) const {
        call("on_exec_error", *m_on_exec_error, exec, ec);
    }

    template<typename Executor>
    DLLLOCAL void call(const char* info,
              const ResolvedCallReferenceNode* callref,
              Executor& exec,
              const std::error_code& ec) const {
        if (!callref) {
            //std::cout << "    info: " << info << ": no handler installed" << std::endl;
            return;
        }

        ReferenceHolder<QoreHashNode> report(new QoreHashNode(autoTypeInfo), m_xsink);
        report->setKeyValue("name", new QoreStringNode(info), m_xsink);
        report->setKeyValue("exe", new QoreStringNode(exec.exe), m_xsink);
#ifndef WINDOWS_API
        report->setKeyValue("pid", exec.pid, m_xsink);
#else
        report->setKeyValue("pid", exec.proc_info.dwProcessId, m_xsink);
#endif
        report->setKeyValue("exit", exec.exit_status.get()->load(), m_xsink);

        // std::error_code& ec to hash too
        report->setKeyValue("error_code", ec.value(), m_xsink);
        report->setKeyValue("error_message", new QoreStringNode(ec.message()), m_xsink);
        report->setKeyValue("error_category", new QoreStringNode(ec.category().name()), m_xsink);

        ReferenceHolder<QoreListNode> args(new QoreListNode(autoTypeInfo), m_xsink);
        args->push(report.release(), m_xsink);
        callref->execValue(*args, m_xsink);
    }

    template<typename Executor>
    DLLLOCAL std::function<void(int, const std::error_code&)> on_exit_handler(Executor& exec) {
        boost::asio::io_context& ios = ex::get_io_context(exec.seq);
        return [this, &ios](int exit_code, const std::error_code& ec) {
            ios.stop();
            ios.run();

#if defined(BOOST_POSIX_API)
            if (WIFEXITED(exit_code)) {
                this->exit_code = WEXITSTATUS(exit_code);
                //printd(5, "on_exit_handler() set exit_code: %d\n", exit_code);
            }
#else
            this->exit_code = exit_code;
#endif
        };
    }

private:
    ExceptionSink* m_xsink;
    int& exit_code;

    ReferenceHolder<ResolvedCallReferenceNode> m_on_success;
    ReferenceHolder<ResolvedCallReferenceNode> m_on_setup;
    ReferenceHolder<ResolvedCallReferenceNode> m_on_error;
    ReferenceHolder<ResolvedCallReferenceNode> m_on_fork_error;
    ReferenceHolder<ResolvedCallReferenceNode> m_on_exec_setup;
    ReferenceHolder<ResolvedCallReferenceNode> m_on_exec_error;
};

#endif
