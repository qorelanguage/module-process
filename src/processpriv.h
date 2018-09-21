#ifndef PROCESSPRIV_H
#define PROCESSPRIV_H

// std
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>

// boost
#include <boost/asio.hpp>
#include <boost/process.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/system/error_code.hpp>

// qore
#include <qore/Qore.h>

DLLLOCAL extern qore_classid_t CID_PROCESS;
DLLLOCAL extern QoreClass* QC_PROCESS;

namespace bp = boost::process;

class ProcessPriv : public AbstractPrivateData {
protected:
    DLLLOCAL virtual ~ProcessPriv();

public:
    DLLLOCAL ProcessPriv(pid_t pid, ExceptionSink* xsink);

    DLLLOCAL ProcessPriv(const char* command, const QoreListNode* arguments, const QoreHashNode* opts, ExceptionSink* xsink);

    DLLLOCAL int exitCode(ExceptionSink* xsink);

    DLLLOCAL int id(ExceptionSink* xsink);

    DLLLOCAL bool valid(ExceptionSink* xsink);

    DLLLOCAL bool running(ExceptionSink* xsink);

    DLLLOCAL bool wait(ExceptionSink* xsink);

    DLLLOCAL bool wait(int64 t, ExceptionSink* xsink);

    DLLLOCAL bool detach(ExceptionSink* xsink);

    DLLLOCAL bool terminate(ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stderr.
    DLLLOCAL QoreValue readStderr(size_t n, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stderr. Wait up to \c millis milliseconds if there is no data.
    DLLLOCAL QoreValue readStderrTimeout(size_t n, int64 millis, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stdout.
    DLLLOCAL QoreValue readStdout(size_t n, ExceptionSink* xsink);

    //! Read up to \c n bytes from process's stdout. Wait up to \c millis milliseconds if there is no data.
    DLLLOCAL QoreValue readStdoutTimeout(size_t n, int64 millis, ExceptionSink* xsink);

    //! Write to child process's stdin.
    DLLLOCAL void write(const char* val, size_t n, ExceptionSink* xsink);

    DLLLOCAL static boost::filesystem::path optsPath(const char* command, const QoreHashNode* opts, ExceptionSink* xsink);

    DLLLOCAL static QoreHashNode* getMemorySummaryInfo(int pid, ExceptionSink* xsink);

    DLLLOCAL static bool checkPid(int pid, ExceptionSink* xsink);

    DLLLOCAL static void terminate(int pid, ExceptionSink* xsink);

    DLLLOCAL static void waitForTermination(int pid, ExceptionSink* xsink);

private:
    const ResolvedCallReferenceNode* optsExecutor(const char* name, const QoreHashNode* opts, ExceptionSink* xsink);

    bp::environment optsEnv(const QoreHashNode* opts, ExceptionSink* xsink);
    const char* optsCwd(const QoreHashNode* opts, ExceptionSink* xsink);

    //! Process exe arguments passed through constructor.
    void processArgs(const QoreListNode* arguments, std::vector<std::string>& out);
    
    //! Prepare stdin ASIO buffer for use in async_write operation.
    void prepareStdinBuffer();

#ifdef __linux__
    DLLLOCAL static QoreHashNode* getMemorySummaryInfoLinux(int pid, ExceptionSink* xsink);
#endif
#if defined(__APPLE__) && defined(__MACH__)
    DLLLOCAL static QoreHashNode* getMemorySummaryInfoDarwin(int pid, ExceptionSink* xsink);
#endif

    //! Thread-safe input buffer. Used for writing to child process's stdin.
    class InputBuffer {
    public:
        InputBuffer() = default;
        ~InputBuffer() {
            m_cv.notify_all();
        }

        //! Get size of data currently in buffer.
        size_t size() {
            return m_buf.size();
        }

        //! Write data into the input buffer.
        void write(const char* src, size_t n) {
            if (!src || !n)
                return;

            std::lock_guard<std::mutex> lock(m_mtx);
            m_buf.append(src, n);
        }

        //! Extract data from the input buffer.
        size_t extract(std::vector<char>& dest, size_t n) {
            if (!n)
                return 0;

            std::lock_guard<std::mutex> lock(m_mtx);

            // fix the read size
            if (m_buf.size() < n)
                n = m_buf.size();

            dest.resize(n);
            m_buf.copy(dest.data(), n, 0);
            m_buf.erase(0, n);
            return n;
        }

    private:
        std::mutex m_mtx;
        std::condition_variable m_cv;
        std::string m_buf;
    };

    //! Thread-safe output buffer. Used for storing data from child process's stdout and stderr.
    class OutputBuffer {
    public:
        OutputBuffer() = default;
        ~OutputBuffer() {
            m_cv.notify_all();
        }

        //! Read from the buffer and return instantly if there is no data.
        size_t read(char* dest, size_t n) {
            if (!dest || !n)
                return 0;

            //std::lock_guard<std::mutex> lock(m_mutex);
            std::unique_lock<std::mutex> lock(m_mtx);

            // return immediately if there is no data
            if (m_buf.size() == 0)
                return 0;

            return doRead(dest, n);
        }

        //! Read from the buffer and return if there is no data after timeout period.
        size_t readTimeout(char* dest, size_t n, int64 millis) {
            if (!dest || !n)
                return 0;

            auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
            std::unique_lock<std::mutex> lock(m_mtx);

            // wait if there is no data
            if (m_buf.size() == 0) {
                m_cv.wait_until(lock, until, [this]{ return m_buf.size() > 0; });

                // return if there is still no data after timeout
                if (m_buf.size() == 0)
                    return 0;
            }

            return doRead(dest, n);
        }

        //! Append data to the buffer.
        void append(const char* src, size_t n) {
            if (!src || !n)
                return;

            {
                std::lock_guard<std::mutex> lock(m_mtx);
                m_buf.append(src, n);
            }

            // notify outside of the lock
            m_cv.notify_all();
        }

    private:
        std::mutex m_mtx;
        std::condition_variable m_cv;
        std::string m_buf;

        //! Read data from buffer in to the destination. Expects that mutex is locked.
        size_t doRead(char* dest, size_t n) {
            // fix the read size
            if (m_buf.size() < n)
                n = m_buf.size();

            m_buf.copy(dest, n, 0);
            m_buf.erase(0, n);
            return n;
        }
    };

    ExceptionSink* m_xsink = nullptr;

    //! Child process.
    bp::child* m_process = nullptr;

    //! Async context required for async IO.
    boost::asio::io_context m_asio_ctx;

    //! Async context future required for running the context in new thread.
    std::future<void> m_asio_ctx_run_future;

    //! Pipe used for writing to child process's stdin.
    bp::async_pipe m_in_pipe;

    //! Pipe used for reading child process's stdout.
    bp::async_pipe m_out_pipe;

    //! Pipe used for reading child process's stderr.
    bp::async_pipe m_err_pipe;

    //! Mutex covering the @ref m_async_write_running variable.
    std::mutex m_async_write_mtx{};

    //! Used for signifying that async_write operation is running. 
    /**
        Needed because we cannot allow multiple async_write operations to run at the same time.
        More info about this here: https://www.boost.org/doc/libs/1_67_0/doc/html/boost_asio/reference/async_write/overload5.html
     */
    int m_async_write_running = 0;

    //! Buffer containg data that should be written to child process's stdin.
    InputBuffer m_in_buf{};

    OutputBuffer m_out_buf{}; //!< Buffer containg data read from child process's stdout.
    OutputBuffer m_err_buf{}; //!< Buffer containg data read from child process's stderr.

    //! Vector containing data currently being written to child process's stdin.
    std::vector<char> m_in_vec{};

    //! Vector where data read from child process's stdout is written before being copied to @ref m_out_buf.
    std::vector<char> m_out_vec{};

    //! Vector where data read from child process's stderr is written before being copied to @ref m_err_buf.
    std::vector<char> m_err_vec{};

    boost::asio::const_buffer m_in_asiobuf;    //!< Buffer wrapping the stdin vector.
    boost::asio::mutable_buffer m_out_asiobuf; //!< Buffer wrapping the stdout vector.
    boost::asio::mutable_buffer m_err_asiobuf; //!< Buffer wrapping the stderr vector.

    //! Closure called after stdin async_write operation is completed.
    std::function<void(const boost::system::error_code& ec, size_t n)> m_on_stdin_complete;

    //! Closure called after stdout async_read operation is completed.
    std::function<void(const boost::system::error_code& ec, size_t n)> m_on_stdout_complete;

    //! Closure called after stderr async_read operation is completed.
    std::function<void(const boost::system::error_code& ec, size_t n)> m_on_stderr_complete;
};

#endif
