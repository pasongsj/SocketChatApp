# Makefile

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Isrc
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
	$(CXX) $(CXXFLAGS) -o $@ $(OBJECTS)

# Compile each source file
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(OBJDIR) log
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -rf log

