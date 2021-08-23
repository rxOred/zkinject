# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.21

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/rxored/repos/zkinject

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/rxored/repos/zkinject/build

# Include any dependencies generated for this target.
include CMakeFiles/libzkinject.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/libzkinject.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/libzkinject.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/libzkinject.dir/flags.make

CMakeFiles/libzkinject.dir/src/zkelf.cc.o: CMakeFiles/libzkinject.dir/flags.make
CMakeFiles/libzkinject.dir/src/zkelf.cc.o: ../src/zkelf.cc
CMakeFiles/libzkinject.dir/src/zkelf.cc.o: CMakeFiles/libzkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/libzkinject.dir/src/zkelf.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/libzkinject.dir/src/zkelf.cc.o -MF CMakeFiles/libzkinject.dir/src/zkelf.cc.o.d -o CMakeFiles/libzkinject.dir/src/zkelf.cc.o -c /home/rxored/repos/zkinject/src/zkelf.cc

CMakeFiles/libzkinject.dir/src/zkelf.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libzkinject.dir/src/zkelf.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zkelf.cc > CMakeFiles/libzkinject.dir/src/zkelf.cc.i

CMakeFiles/libzkinject.dir/src/zkelf.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libzkinject.dir/src/zkelf.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zkelf.cc -o CMakeFiles/libzkinject.dir/src/zkelf.cc.s

CMakeFiles/libzkinject.dir/src/zkproc.cc.o: CMakeFiles/libzkinject.dir/flags.make
CMakeFiles/libzkinject.dir/src/zkproc.cc.o: ../src/zkproc.cc
CMakeFiles/libzkinject.dir/src/zkproc.cc.o: CMakeFiles/libzkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/libzkinject.dir/src/zkproc.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/libzkinject.dir/src/zkproc.cc.o -MF CMakeFiles/libzkinject.dir/src/zkproc.cc.o.d -o CMakeFiles/libzkinject.dir/src/zkproc.cc.o -c /home/rxored/repos/zkinject/src/zkproc.cc

CMakeFiles/libzkinject.dir/src/zkproc.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libzkinject.dir/src/zkproc.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zkproc.cc > CMakeFiles/libzkinject.dir/src/zkproc.cc.i

CMakeFiles/libzkinject.dir/src/zkproc.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libzkinject.dir/src/zkproc.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zkproc.cc -o CMakeFiles/libzkinject.dir/src/zkproc.cc.s

# Object files for target libzkinject
libzkinject_OBJECTS = \
"CMakeFiles/libzkinject.dir/src/zkelf.cc.o" \
"CMakeFiles/libzkinject.dir/src/zkproc.cc.o"

# External object files for target libzkinject
libzkinject_EXTERNAL_OBJECTS =

liblibzkinject.so.0.1: CMakeFiles/libzkinject.dir/src/zkelf.cc.o
liblibzkinject.so.0.1: CMakeFiles/libzkinject.dir/src/zkproc.cc.o
liblibzkinject.so.0.1: CMakeFiles/libzkinject.dir/build.make
liblibzkinject.so.0.1: CMakeFiles/libzkinject.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/rxored/repos/zkinject/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX shared library liblibzkinject.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/libzkinject.dir/link.txt --verbose=$(VERBOSE)
	$(CMAKE_COMMAND) -E cmake_symlink_library liblibzkinject.so.0.1 liblibzkinject.so.1 liblibzkinject.so

liblibzkinject.so.1: liblibzkinject.so.0.1
	@$(CMAKE_COMMAND) -E touch_nocreate liblibzkinject.so.1

liblibzkinject.so: liblibzkinject.so.0.1
	@$(CMAKE_COMMAND) -E touch_nocreate liblibzkinject.so

# Rule to build all files generated by this target.
CMakeFiles/libzkinject.dir/build: liblibzkinject.so
.PHONY : CMakeFiles/libzkinject.dir/build

CMakeFiles/libzkinject.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/libzkinject.dir/cmake_clean.cmake
.PHONY : CMakeFiles/libzkinject.dir/clean

CMakeFiles/libzkinject.dir/depend:
	cd /home/rxored/repos/zkinject/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rxored/repos/zkinject /home/rxored/repos/zkinject /home/rxored/repos/zkinject/build /home/rxored/repos/zkinject/build /home/rxored/repos/zkinject/build/CMakeFiles/libzkinject.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/libzkinject.dir/depend
