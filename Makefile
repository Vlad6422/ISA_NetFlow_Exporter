# Define the compiler
CXX = g++

# Define the target executable
TARGET = p2nprobe

# Define the source and header files
SRC = p2nprobe.cpp
HDR = p2nprobe.hpp

# Define compiler flags
CXXFLAGS = -Wall -O2

# Define linker flags
LDFLAGS = -lpcap

# Rule to build the target
$(TARGET): $(SRC) $(HDR)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Clean rule to remove the generated executable
clean:
	rm -f $(TARGET)

.PHONY: clean
