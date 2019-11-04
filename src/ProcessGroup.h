/*
    Qore Programming Language process Module

    Copyright (C) 2003 - 2019 Qore Technologies, s.r.o.

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

#ifndef PROCESSGROUP_H_OVVHGZLSGA2DQSBVNZZWIMBT
#define PROCESSGROUP_H_OVVHGZLSGA2DQSBVNZZWIMBT

// std
#include <csignal>
#include <cstddef>

// boost
#include <boost/process.hpp>

// qore
#include <qore/Qore.h>

DLLLOCAL extern qore_classid_t CID_PROCESSGROUP;
DLLLOCAL extern QoreClass* QC_PROCESSGROUP;

namespace bp = boost::process;

class ProcessGroup : public AbstractPrivateData {
protected:
    DLLLOCAL virtual ~ProcessGroup();

public:
    DLLLOCAL ProcessGroup(ExceptionSink* xsink);

    DLLLOCAL bp::group& getGroup() { return *m_group; }

    DLLLOCAL void setUsedForProcess();

    DLLLOCAL bool usedCheck(ExceptionSink* xsink);

    DLLLOCAL bool valid(ExceptionSink* xsink);

    DLLLOCAL bool wait(ExceptionSink* xsink);

    DLLLOCAL bool wait(int64 t, ExceptionSink* xsink);

    DLLLOCAL bool detach(ExceptionSink* xsink);

    DLLLOCAL bool terminate(ExceptionSink* xsink);

    DLLLOCAL static pid_t getPgid(pid_t pid, ExceptionSink* xsink);

    DLLLOCAL static void kill(pid_t pgid, int signal = SIGTERM, ExceptionSink* xsink = nullptr);

    DLLLOCAL static void terminate(pid_t pgid, ExceptionSink* xsink);

private:
    ExceptionSink* m_xsink = nullptr;

    //! Process group.
    bp::group* m_group = nullptr;

    //! Whether group has been used for a process.
    bool m_usedForProcess = false;
};

#endif // PROCESSGROUP_H_OVVHGZLSGA2DQSBVNZZWIMBT
