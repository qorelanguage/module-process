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

#include "ProcessGroup.h"

// std
#include <chrono>
#include <exception>

// module
#include "unix-config.h"

namespace bp = boost::process;

ProcessGroup::ProcessGroup(ExceptionSink* xsink) :
    m_xsink(xsink)
{
    m_group = new bp::group();
}

ProcessGroup::~ProcessGroup() {
    if (m_group)
        delete m_group;
    m_group = nullptr;
}

void ProcessGroup::setUsedForProcess() {
    m_usedForProcess = true;
}

bool ProcessGroup::usedCheck(ExceptionSink* xsink) {
    if (!m_usedForProcess) {
        if (xsink) {
            xsink->raiseException(
                "PROCESS-GROUP-CHECK-ERROR",
                "process group has not been used for any process and using it is therefore undefined behavior"
            );
        }
        return false;
    }
    return true;
}

bool ProcessGroup::valid(ExceptionSink* xsink) {
    if (!usedCheck(xsink)) {
        return false;
    }

    try {
        return m_group->valid();
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-GROUP-VALID-ERROR", ex.what());
    }

    return false;
}

bool ProcessGroup::wait(ExceptionSink* xsink) {
    if (!usedCheck(xsink)) {
        return false;
    }

    try {
        if (m_group->valid()) {
            m_group->wait();
            return true;
        }
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-GROUP-WAIT-ERROR", ex.what());
    }

    return false;
}

bool ProcessGroup::wait(int64 t, ExceptionSink* xsink) {
    if (!usedCheck(xsink)) {
        return false;
    }

    try {
        if (m_group->valid()) {
            return m_group->wait_for(std::chrono::milliseconds(t));
        }
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-GROUP-WAIT-ERROR", ex.what());
    }

    return false;
}

bool ProcessGroup::detach(ExceptionSink* xsink) {
    if (!usedCheck(xsink)) {
        return false;
    }

    m_group->detach();
    return true;
}

bool ProcessGroup::terminate(ExceptionSink* xsink) {
    if (!usedCheck(xsink)) {
        return false;
    }

    try {
        m_group->terminate();
        return true;
    } catch (const std::exception& ex) {
        xsink->raiseException("PROCESS-GROUP-TERMINATE-ERROR", ex.what());
    }

    return false;
}

void ProcessGroup::kill(pid_t pgid, int signal, ExceptionSink* xsink) {
#ifdef HAVE_KILLPG
    // pgid 0 would kill the current process group; according to POSIX, less than or equal to 1 is undefined behavior
    if (pgid <= 0) {
        xsink->raiseException("PROCESS-GROUP-KILL-ERROR", "invalid pgid %d; pgid has to be higher than zero", pgid);
        return;
    }
    if (killpg(pgid, signal)) {
        switch (errno) {
            case EPERM:
                xsink->raiseException("PROCESS-GROUP-KILL-ERROR", "insufficient permissions to kill pgid %d", pgid);
                break;
            case EINVAL:
                xsink->raiseException("PROCESS-GROUP-KILL-ERROR", "invalid signal number %d", signal);
                break;
            case ESRCH:
            default:
                xsink->raiseErrnoException("INVALID-PGID-ERROR", errno, "no process group with pgid %d can be found", pgid);
                break;
        }
    }
#elif HAVE_KILL
    // pgid 0 would kill the current process group; according to POSIX, less than or equal to 1 is undefined behavior
    if (pgid <= 0) {
        xsink->raiseException("PROCESS-GROUP-KILL-ERROR", "invalid pgid %d; pgid has to be higher than zero", pgid);
        return;
    }
    if (kill(-pgid, signal)) {
        switch (errno) {
            case EPERM:
                xsink->raiseException("PROCESS-GROUP-KILL-ERROR", "insufficient permissions to kill pgid %d", pgid);
                break;
            case EINVAL:
                xsink->raiseException("PROCESS-GROUP-KILL-ERROR", "invalid signal number %d", signal);
                break;
            case ESRCH:
            default:
                xsink->raiseErrnoException("INVALID-PGID-ERROR", errno, "no process group with pgid %d can be found", pgid);
                break;
        }
    }
#else
    xsink->raiseException("PROCESS-GROUP-KILL-UNSUPPORTED-ERROR", "this call is not supported on this platform");
#endif
}

void ProcessGroup::terminate(pid_t pgid, ExceptionSink* xsink) {
#ifdef HAVE_KILLPG
    // pgid 0 would kill the current process group; according to POSIX, less than or equal to 1 is undefined behavior
    if (pgid <= 1) {
        xsink->raiseException("PROCESS-GROUP-TERMINATE-ERROR", "invalid pgid %d; pgid has to be higher than 1", pgid);
        return;
    }
    if (killpg(pgid, SIGKILL)) {
        switch (errno) {
            case EPERM:
                xsink->raiseException("PROCESS-GROUP-TERMINATE-ERROR", "insufficient permissions to terminate pgid %d", pgid);
                break;
            case ESRCH:
            default:
                xsink->raiseErrnoException("INVALID-PGID-ERROR", errno, "no process group with pgid %d can be found", pgid);
                break;
        }
    }
#elif HAVE_KILL
    // pgid 0 would kill the current process group; according to POSIX, less than or equal to 1 is undefined behavior
    if (pgid <= 1) {
        xsink->raiseException("PROCESS-GROUP-TERMINATE-ERROR", "invalid pgid %d; pgid has to be higher than 1", pgid);
        return;
    }
    if (kill(-pgid, SIGKILL)) {
        switch (errno) {
            case EPERM:
                xsink->raiseException("PROCESS-GROUP-TERMINATE-ERROR", "insufficient permissions to terminate pgid %d", pgid);
                break;
            case ESRCH:
            default:
                xsink->raiseErrnoException("INVALID-PGID-ERROR", errno, "no process group with pgid %d can be found", pgid);
                break;
        }
    }
#else
    xsink->raiseException("PROCESS-GROUP-TERMINATE-UNSUPPORTED-ERROR", "this call is not supported on this platform");
#endif
}

