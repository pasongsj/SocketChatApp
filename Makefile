# Makefile

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Isrc -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
OBJDIR = build
SRCDIR = src
TARGET = $(OBJDIR)/my_socket_app

# Source files
SOURCES = $(SRCDIR)/SocketBase.cpp $(SRCDIR)/SocketClient.cpp $(SRCDIR)/SocketServer.cpp $(SRCDIR)/main.cpp
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Default target
all: $(TARGET)

# Link target
$(TARGET): $(OBJECTS)
	@mkdir -p $(OBJDIR)  # Ensure the build directory exists
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJECTS)

# Compile each source file
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(OBJDIR) log
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -rf $(OBJDIR) log

