# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

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
CMAKE_BINARY_DIR = /home/rxored/repos/zkinject/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/zkinject.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/zkinject.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/zkinject.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/zkinject.dir/flags.make

CMakeFiles/zkinject.dir/src/zkelf.cc.o: CMakeFiles/zkinject.dir/flags.make
CMakeFiles/zkinject.dir/src/zkelf.cc.o: /home/rxored/repos/zkinject/src/zkelf.cc
CMakeFiles/zkinject.dir/src/zkelf.cc.o: CMakeFiles/zkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/zkinject.dir/src/zkelf.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/zkinject.dir/src/zkelf.cc.o -MF CMakeFiles/zkinject.dir/src/zkelf.cc.o.d -o CMakeFiles/zkinject.dir/src/zkelf.cc.o -c /home/rxored/repos/zkinject/src/zkelf.cc

CMakeFiles/zkinject.dir/src/zkelf.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zkinject.dir/src/zkelf.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zkelf.cc > CMakeFiles/zkinject.dir/src/zkelf.cc.i

CMakeFiles/zkinject.dir/src/zkelf.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zkinject.dir/src/zkelf.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zkelf.cc -o CMakeFiles/zkinject.dir/src/zkelf.cc.s

CMakeFiles/zkinject.dir/src/zkhooks.cc.o: CMakeFiles/zkinject.dir/flags.make
CMakeFiles/zkinject.dir/src/zkhooks.cc.o: /home/rxored/repos/zkinject/src/zkhooks.cc
CMakeFiles/zkinject.dir/src/zkhooks.cc.o: CMakeFiles/zkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/zkinject.dir/src/zkhooks.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/zkinject.dir/src/zkhooks.cc.o -MF CMakeFiles/zkinject.dir/src/zkhooks.cc.o.d -o CMakeFiles/zkinject.dir/src/zkhooks.cc.o -c /home/rxored/repos/zkinject/src/zkhooks.cc

CMakeFiles/zkinject.dir/src/zkhooks.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zkinject.dir/src/zkhooks.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zkhooks.cc > CMakeFiles/zkinject.dir/src/zkhooks.cc.i

CMakeFiles/zkinject.dir/src/zkhooks.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zkinject.dir/src/zkhooks.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zkhooks.cc -o CMakeFiles/zkinject.dir/src/zkhooks.cc.s

CMakeFiles/zkinject.dir/src/zklog.cc.o: CMakeFiles/zkinject.dir/flags.make
CMakeFiles/zkinject.dir/src/zklog.cc.o: /home/rxored/repos/zkinject/src/zklog.cc
CMakeFiles/zkinject.dir/src/zklog.cc.o: CMakeFiles/zkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/zkinject.dir/src/zklog.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/zkinject.dir/src/zklog.cc.o -MF CMakeFiles/zkinject.dir/src/zklog.cc.o.d -o CMakeFiles/zkinject.dir/src/zklog.cc.o -c /home/rxored/repos/zkinject/src/zklog.cc

CMakeFiles/zkinject.dir/src/zklog.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zkinject.dir/src/zklog.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zklog.cc > CMakeFiles/zkinject.dir/src/zklog.cc.i

CMakeFiles/zkinject.dir/src/zklog.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zkinject.dir/src/zklog.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zklog.cc -o CMakeFiles/zkinject.dir/src/zklog.cc.s

CMakeFiles/zkinject.dir/src/zkmemorymap.cc.o: CMakeFiles/zkinject.dir/flags.make
CMakeFiles/zkinject.dir/src/zkmemorymap.cc.o: /home/rxored/repos/zkinject/src/zkmemorymap.cc
CMakeFiles/zkinject.dir/src/zkmemorymap.cc.o: CMakeFiles/zkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/zkinject.dir/src/zkmemorymap.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/zkinject.dir/src/zkmemorymap.cc.o -MF CMakeFiles/zkinject.dir/src/zkmemorymap.cc.o.d -o CMakeFiles/zkinject.dir/src/zkmemorymap.cc.o -c /home/rxored/repos/zkinject/src/zkmemorymap.cc

CMakeFiles/zkinject.dir/src/zkmemorymap.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zkinject.dir/src/zkmemorymap.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zkmemorymap.cc > CMakeFiles/zkinject.dir/src/zkmemorymap.cc.i

CMakeFiles/zkinject.dir/src/zkmemorymap.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zkinject.dir/src/zkmemorymap.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zkmemorymap.cc -o CMakeFiles/zkinject.dir/src/zkmemorymap.cc.s

CMakeFiles/zkinject.dir/src/zkprocess.cc.o: CMakeFiles/zkinject.dir/flags.make
CMakeFiles/zkinject.dir/src/zkprocess.cc.o: /home/rxored/repos/zkinject/src/zkprocess.cc
CMakeFiles/zkinject.dir/src/zkprocess.cc.o: CMakeFiles/zkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/zkinject.dir/src/zkprocess.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/zkinject.dir/src/zkprocess.cc.o -MF CMakeFiles/zkinject.dir/src/zkprocess.cc.o.d -o CMakeFiles/zkinject.dir/src/zkprocess.cc.o -c /home/rxored/repos/zkinject/src/zkprocess.cc

CMakeFiles/zkinject.dir/src/zkprocess.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zkinject.dir/src/zkprocess.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zkprocess.cc > CMakeFiles/zkinject.dir/src/zkprocess.cc.i

CMakeFiles/zkinject.dir/src/zkprocess.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zkinject.dir/src/zkprocess.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zkprocess.cc -o CMakeFiles/zkinject.dir/src/zkprocess.cc.s

CMakeFiles/zkinject.dir/src/zkptrace.cc.o: CMakeFiles/zkinject.dir/flags.make
CMakeFiles/zkinject.dir/src/zkptrace.cc.o: /home/rxored/repos/zkinject/src/zkptrace.cc
CMakeFiles/zkinject.dir/src/zkptrace.cc.o: CMakeFiles/zkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/zkinject.dir/src/zkptrace.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/zkinject.dir/src/zkptrace.cc.o -MF CMakeFiles/zkinject.dir/src/zkptrace.cc.o.d -o CMakeFiles/zkinject.dir/src/zkptrace.cc.o -c /home/rxored/repos/zkinject/src/zkptrace.cc

CMakeFiles/zkinject.dir/src/zkptrace.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zkinject.dir/src/zkptrace.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zkptrace.cc > CMakeFiles/zkinject.dir/src/zkptrace.cc.i

CMakeFiles/zkinject.dir/src/zkptrace.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zkinject.dir/src/zkptrace.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zkptrace.cc -o CMakeFiles/zkinject.dir/src/zkptrace.cc.s

CMakeFiles/zkinject.dir/src/zksignal.cc.o: CMakeFiles/zkinject.dir/flags.make
CMakeFiles/zkinject.dir/src/zksignal.cc.o: /home/rxored/repos/zkinject/src/zksignal.cc
CMakeFiles/zkinject.dir/src/zksignal.cc.o: CMakeFiles/zkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/zkinject.dir/src/zksignal.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/zkinject.dir/src/zksignal.cc.o -MF CMakeFiles/zkinject.dir/src/zksignal.cc.o.d -o CMakeFiles/zkinject.dir/src/zksignal.cc.o -c /home/rxored/repos/zkinject/src/zksignal.cc

CMakeFiles/zkinject.dir/src/zksignal.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zkinject.dir/src/zksignal.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zksignal.cc > CMakeFiles/zkinject.dir/src/zksignal.cc.i

CMakeFiles/zkinject.dir/src/zksignal.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zkinject.dir/src/zksignal.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zksignal.cc -o CMakeFiles/zkinject.dir/src/zksignal.cc.s

CMakeFiles/zkinject.dir/src/zksnapshot.cc.o: CMakeFiles/zkinject.dir/flags.make
CMakeFiles/zkinject.dir/src/zksnapshot.cc.o: /home/rxored/repos/zkinject/src/zksnapshot.cc
CMakeFiles/zkinject.dir/src/zksnapshot.cc.o: CMakeFiles/zkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object CMakeFiles/zkinject.dir/src/zksnapshot.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/zkinject.dir/src/zksnapshot.cc.o -MF CMakeFiles/zkinject.dir/src/zksnapshot.cc.o.d -o CMakeFiles/zkinject.dir/src/zksnapshot.cc.o -c /home/rxored/repos/zkinject/src/zksnapshot.cc

CMakeFiles/zkinject.dir/src/zksnapshot.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zkinject.dir/src/zksnapshot.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zksnapshot.cc > CMakeFiles/zkinject.dir/src/zksnapshot.cc.i

CMakeFiles/zkinject.dir/src/zksnapshot.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zkinject.dir/src/zksnapshot.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zksnapshot.cc -o CMakeFiles/zkinject.dir/src/zksnapshot.cc.s

CMakeFiles/zkinject.dir/src/zkutils.cc.o: CMakeFiles/zkinject.dir/flags.make
CMakeFiles/zkinject.dir/src/zkutils.cc.o: /home/rxored/repos/zkinject/src/zkutils.cc
CMakeFiles/zkinject.dir/src/zkutils.cc.o: CMakeFiles/zkinject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object CMakeFiles/zkinject.dir/src/zkutils.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/zkinject.dir/src/zkutils.cc.o -MF CMakeFiles/zkinject.dir/src/zkutils.cc.o.d -o CMakeFiles/zkinject.dir/src/zkutils.cc.o -c /home/rxored/repos/zkinject/src/zkutils.cc

CMakeFiles/zkinject.dir/src/zkutils.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zkinject.dir/src/zkutils.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rxored/repos/zkinject/src/zkutils.cc > CMakeFiles/zkinject.dir/src/zkutils.cc.i

CMakeFiles/zkinject.dir/src/zkutils.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zkinject.dir/src/zkutils.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rxored/repos/zkinject/src/zkutils.cc -o CMakeFiles/zkinject.dir/src/zkutils.cc.s

# Object files for target zkinject
zkinject_OBJECTS = \
"CMakeFiles/zkinject.dir/src/zkelf.cc.o" \
"CMakeFiles/zkinject.dir/src/zkhooks.cc.o" \
"CMakeFiles/zkinject.dir/src/zklog.cc.o" \
"CMakeFiles/zkinject.dir/src/zkmemorymap.cc.o" \
"CMakeFiles/zkinject.dir/src/zkprocess.cc.o" \
"CMakeFiles/zkinject.dir/src/zkptrace.cc.o" \
"CMakeFiles/zkinject.dir/src/zksignal.cc.o" \
"CMakeFiles/zkinject.dir/src/zksnapshot.cc.o" \
"CMakeFiles/zkinject.dir/src/zkutils.cc.o"

# External object files for target zkinject
zkinject_EXTERNAL_OBJECTS =

libzkinject.so.0.1: CMakeFiles/zkinject.dir/src/zkelf.cc.o
libzkinject.so.0.1: CMakeFiles/zkinject.dir/src/zkhooks.cc.o
libzkinject.so.0.1: CMakeFiles/zkinject.dir/src/zklog.cc.o
libzkinject.so.0.1: CMakeFiles/zkinject.dir/src/zkmemorymap.cc.o
libzkinject.so.0.1: CMakeFiles/zkinject.dir/src/zkprocess.cc.o
libzkinject.so.0.1: CMakeFiles/zkinject.dir/src/zkptrace.cc.o
libzkinject.so.0.1: CMakeFiles/zkinject.dir/src/zksignal.cc.o
libzkinject.so.0.1: CMakeFiles/zkinject.dir/src/zksnapshot.cc.o
libzkinject.so.0.1: CMakeFiles/zkinject.dir/src/zkutils.cc.o
libzkinject.so.0.1: CMakeFiles/zkinject.dir/build.make
libzkinject.so.0.1: CMakeFiles/zkinject.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Linking CXX shared library libzkinject.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/zkinject.dir/link.txt --verbose=$(VERBOSE)
	$(CMAKE_COMMAND) -E cmake_symlink_library libzkinject.so.0.1 libzkinject.so.1 libzkinject.so

libzkinject.so.1: libzkinject.so.0.1
	@$(CMAKE_COMMAND) -E touch_nocreate libzkinject.so.1

libzkinject.so: libzkinject.so.0.1
	@$(CMAKE_COMMAND) -E touch_nocreate libzkinject.so

# Rule to build all files generated by this target.
CMakeFiles/zkinject.dir/build: libzkinject.so
.PHONY : CMakeFiles/zkinject.dir/build

CMakeFiles/zkinject.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/zkinject.dir/cmake_clean.cmake
.PHONY : CMakeFiles/zkinject.dir/clean

CMakeFiles/zkinject.dir/depend:
	cd /home/rxored/repos/zkinject/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rxored/repos/zkinject /home/rxored/repos/zkinject /home/rxored/repos/zkinject/cmake-build-debug /home/rxored/repos/zkinject/cmake-build-debug /home/rxored/repos/zkinject/cmake-build-debug/CMakeFiles/zkinject.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/zkinject.dir/depend

