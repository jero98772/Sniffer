#!/bin/bash

# Ensure we have the C packet capture program compiled
echo "Compiling the packet capture program..."
gcc -o packet_capture packet_capture.c

# Create project structure
echo "Setting up Clojure project structure..."
mkdir -p packet-capture/src/packet_capture/
mkdir -p packet-capture/resources/public/

# Copy files
echo "Moving source files to project..."
cp clojure-packet-capture.clj packet-capture/src/packet_capture/core.clj
cp project.clj packet-capture/

# Make sure Leiningen is installed
if ! command -v lein &> /dev/null; then
    echo "Leiningen not found. Please install it first:"
    echo "https://leiningen.org/#install"
    exit 1
fi

# Move to project directory and run
cd packet-capture
echo "Starting the Clojure application..."
lein run

# Note: You'll need to run with sudo for raw socket access
# sudo lein run