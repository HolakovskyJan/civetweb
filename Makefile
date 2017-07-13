#
# Copyright (c) 2013 No Face Press, LLC
# License http://opensource.org/licenses/mit-license.php MIT License
#

#
# For help try, "make help"
#

CPROG = civetweb

BUILD_DIR = out

# build tools
MKDIR = mkdir -p
RMF = rm -f
RMRF = rm -rf

BUILD_DIRS = $(BUILD_DIR) $(BUILD_DIR)/src

LIB_SOURCES = src/civetweb.c
LIB_INLINE  = src/md5.inl
APP_SOURCES = src/main.c
WINDOWS_RESOURCES = resources/res.rc
SOURCE_DIRS =

OBJECTS = $(LIB_SOURCES:.c=.o) $(APP_SOURCES:.c=.o)
BUILD_RESOURCES =

# only set main compile options if none were chosen
CFLAGS += -Wall -Wextra -Wshadow -Wformat-security -Winit-self -Wmissing-prototypes -D$(TARGET_OS) -Iinclude $(COPT) -DUSE_STACK_SIZE=102400

LIBS = -lpthread -lm

ifdef WITH_DEBUG
  CFLAGS += -g -DDEBUG
else
  CFLAGS += -O2 -DNDEBUG
endif

ifdef WITH_IPV6
  CFLAGS += -DUSE_IPV6
endif

ifdef WITH_WEBSOCKET
  CFLAGS += -DUSE_WEBSOCKET
endif
ifdef WITH_WEBSOCKETS
  CFLAGS += -DUSE_WEBSOCKET
endif

ifdef WITH_SERVER_STAT
  CFLAGS += -DUSE_SERVER_STATS
endif
ifdef WITH_SERVER_STATS
  CFLAGS += -DUSE_SERVER_STATS
endif

ifdef SSL_LIB
  CFLAGS += -DSSL_LIB=\"$(SSL_LIB)\"
endif

ifdef CRYPTO_LIB
  CFLAGS += -DCRYPTO_LIB=\"$(CRYPTO_LIB)\"
endif

BUILD_DIRS += $(addprefix $(BUILD_DIR)/, $(SOURCE_DIRS))
BUILD_OBJECTS = $(addprefix $(BUILD_DIR)/, $(OBJECTS))
MAIN_OBJECTS = $(addprefix $(BUILD_DIR)/, $(APP_SOURCES:.c=.o))
LIB_OBJECTS = $(filter-out $(MAIN_OBJECTS), $(BUILD_OBJECTS))

ifeq ($(TARGET_OS),LINUX)
  LIBS += -lrt -ldl
endif

ifeq ($(TARGET_OS),WIN32)
  MKDIR = mkdir
  RMF = del /q
  RMRF = rmdir /s /q
endif

ifneq (, $(findstring mingw32, $(shell $(CC) -dumpmachine)))
  BUILD_RESOURCES = $(BUILD_DIR)/$(WINDOWS_RESOURCES:.rc=.o)
  LIBS += -lws2_32 -mwindows
  SHARED_LIB = dll
else
  SHARED_LIB = so
endif

all: build

help:
	@echo "make help                show this message"
	@echo "make build               compile"
	@echo "make clean               clean up the mess"
	@echo "make lib                 build a static library"
	@echo "make slib                build a shared library"
	@echo ""
	@echo " Make Options"
	@echo "   WITH_DEBUG=1          build with GDB debug support"
	@echo "   WITH_IPV6=1           with IPV6 support"
	@echo "   WITH_WEBSOCKET=1      build with web socket support"
	@echo "   WITH_SERVER_STATS=1   build includes support for server statistics"
	@echo "   SSL_LIB=libssl.so.0   use versioned SSL library"
	@echo "   CRYPTO_LIB=libcrypto.so.0 system versioned CRYPTO library"
	@echo "   PREFIX=/usr/local     sets the install directory"
	@echo "   COPT='-DNO_SSL'       method to insert compile flags"
	@echo ""
	@echo " Compile Flags"
	@echo "   NDEBUG                strip off all debug code"
	@echo "   DEBUG                 build debug version (very noisy)"
	@echo "   NO_CGI                disable CGI support"
	@echo "   NO_SSL                disable SSL functionality"
	@echo "   NO_SSL_DL             link against system libssl library"
	@echo "   NO_FILES              do not serve files from a directory"
	@echo "   NO_CACHING            disable caching (usefull for systems without timegm())"
	@echo ""
	@echo " Variables"
	@echo "   TARGET_OS='$(TARGET_OS)'"
	@echo "   CFLAGS='$(CFLAGS)'"
	@echo "   CXXFLAGS='$(CXXFLAGS)'"
	@echo "   LDFLAGS='$(LDFLAGS)'"
	@echo "   CC='$(CC)'"
	@echo "   CXX='$(CXX)'"

build: $(CPROG) $(CXXPROG)

lib: lib$(CPROG).a

slib: lib$(CPROG).$(SHARED_LIB)

clean:
	$(RMRF) $(BUILD_DIR)
	$(eval version=$(shell grep -w "define CIVETWEB_VERSION" include/civetweb.h | sed 's|.*VERSION "\(.*\)"|\1|g'))
	$(eval major=$(shell echo $(version) | cut -d'.' -f1))
	$(RMRF) lib$(CPROG).a
	$(RMRF) lib$(CPROG).so
	$(RMRF) lib$(CPROG).so.$(major)
	$(RMRF) lib$(CPROG).so.$(version).0
	$(RMRF) $(CPROG)
	$(RMF) $(UNIT_TEST_PROG)

distclean: clean
	@$(RMRF) VS2012/Debug VS2012/*/Debug  VS2012/*/*/Debug
	@$(RMRF) VS2012/Release VS2012/*/Release  VS2012/*/*/Release
	$(RMF) $(CPROG) lib$(CPROG).so lib$(CPROG).a *.dmg *.msi *.exe lib$(CPROG).dll lib$(CPROG).dll.a
	$(RMF) $(UNIT_TEST_PROG)

lib$(CPROG).a: CFLAGS += -fPIC
lib$(CPROG).a: $(LIB_OBJECTS)
	@$(RMF) $@
	ar cq $@ $(LIB_OBJECTS)

lib$(CPROG).so: CFLAGS += -fPIC
lib$(CPROG).so: $(LIB_OBJECTS)
	$(eval version=$(shell grep -w "define CIVETWEB_VERSION" include/civetweb.h | sed 's|.*VERSION "\(.*\)"|\1|g'))
	$(eval major=$(shell echo $(version) | cut -d'.' -f1))
	$(LCC) -shared -Wl,-soname,$@.$(major) -o $@.$(version).0 $(CFLAGS) $(LDFLAGS) $(LIB_OBJECTS)
	ln -s -f $@.$(major) $@
	ln -s -f $@.$(version).0 $@.$(major)

lib$(CPROG).dll: CFLAGS += -fPIC
lib$(CPROG).dll: $(LIB_OBJECTS)
	$(LCC) -shared -o $@ $(CFLAGS) $(LDFLAGS) $(LIB_OBJECTS) $(LIBS) -Wl,--out-implib,lib$(CPROG).dll.a

$(CPROG): $(BUILD_OBJECTS) $(BUILD_RESOURCES)
	$(LCC) -o $@ $(CFLAGS) $(LDFLAGS) $(BUILD_OBJECTS) $(BUILD_RESOURCES) $(LIBS)

$(CXXPROG): $(BUILD_OBJECTS)
	$(CXX) -o $@ $(CFLAGS) $(LDFLAGS) $(BUILD_OBJECTS) $(LIBS)

$(BUILD_OBJECTS): $(BUILD_DIRS)

$(BUILD_DIRS):
	-@$(MKDIR) "$@"

$(BUILD_DIR)/%.o : %.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $< -o $@

$(BUILD_DIR)/%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_RESOURCES) : $(WINDOWS_RESOURCES)
	windres $(WINDRES_FLAGS) $< $@

# This rules is used to keep the code formatted in a reasonable manor
# For this to work astyle must be installed and in the path
# http://sourceforge.net/projects/astyle
indent:
	astyle --suffix=none --style=linux --indent=spaces=4 --lineend=linux  include/*.h src/*.c src/*.cpp src/*.inl examples/*/*.c  examples/*/*.cpp

.PHONY: all help build clean lib so
