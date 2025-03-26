
# EECCFrog512 Makefile - Build system for your custom 512-bit elliptic curve
# ---------------------------------------------------------
# Author: Porquinho & SapoGPT
# Description:
#   Compiles the ECCFrog512 library and example using OpenSSL.
#   Creates the bin directory automatically.
#   Supports clean, debug, release, install-ready setups.
# ---------------------------------------------------------

# Directories
SRC_DIR     = .
INCLUDE_DIR = .
BIN_DIR     = bin
TARGET      = $(BIN_DIR)/eccfrog_example

# Compiler and flags
CXX         = g++
CXXFLAGS    = -Wall -Wextra -std=c++17 -O2 -I$(INCLUDE_DIR)
LDFLAGS     = -lssl -lcrypto

# Sources
SRCS        = $(SRC_DIR)/eccfrog512.cpp $(SRC_DIR)/example.cpp

# Object files
OBJS        = $(SRCS:.cpp=.o)

# Default target
all: prepare $(TARGET)

# Prepare bin directory
prepare:
	@mkdir -p $(BIN_DIR)

# Link everything into target binary
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: clean all

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR) *.o *.dSYM

# Install to /usr/local/bin (optional)
install: all
	cp $(TARGET) /usr/local/bin/eccfrog_example

# Uninstall
uninstall:
	rm -f /usr/local/bin/eccfrog_example

.PHONY: all clean debug install uninstall prepare
