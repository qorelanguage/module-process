#!/usr/bin/env qore
%new-style

# Simple script that handles SIGTERM gracefully
bool running = True;

set_signal_handler(SIGTERM, sub() {
    stdout.print("SIGTERM received");
    running = False;
});

# Keep running until signal received
while (running) {
    sleep(100ms);
}

exit(0);
