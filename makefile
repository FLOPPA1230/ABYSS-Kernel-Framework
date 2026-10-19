CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wcast-qual \
            -Wwrite-strings -Wpointer-arith -Wstrict-prototypes \
            -Wmissing-prototypes -Wno-unused-parameter -pthread
LDFLAGS  ?= -pthread
LDLIBS   ?= 
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
SRCDIR   ?= .
OBJDIR   ?= build

TARGET   := abyss
SRCS     := main.c ipc.c report.c acpi.c fuzz.c hyper.c
OBJS     := $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS     := $(OBJS:.o=.d)
HDRS     := abyss.h

VERSION  := 1.0.0
DATE     := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

CFLAGS   += -DABYSS_BUILD_VERSION=\"$(VERSION)\" -DABYSS_BUILD_DATE=\"$(DATE)\"

.PHONY: all debug release clean install uninstall run test help \
        format analyze sanitize valgrind dirs

all: release

release: CFLAGS += -DNDEBUG
release: dirs $(TARGET)

debug: CFLAGS += -g3 -O0 -fno-omit-frame-pointer -DDEBUG
debug: LDFLAGS += -g3
debug: dirs $(TARGET)

sanitize: CFLAGS += -g3 -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize: LDFLAGS += -fsanitize=address,undefined
sanitize: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJDIR)

$(TARGET): $(OBJS)
	@echo "  LD      $@"
	@$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
	@echo "  OK      $@ built ($$(stat -c%s $@ 2>/dev/null || echo '?') bytes)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HDRS) | dirs
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

clean:
	@echo "  CLEAN   removing build artifacts"
	@rm -rf $(OBJDIR) $(TARGET) *.d
	@rm -rf abyss_report

install: release
	@echo "  INSTALL $(DESTDIR)$(BINDIR)/$(TARGET)"
	@install -d $(DESTDIR)$(BINDIR)
	@install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	@echo "  REMOVE  $(DESTDIR)$(BINDIR)/$(TARGET)"
	@rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

run: debug
	@echo "  RUN     ./$(TARGET) --all --verbose"
	@./$(TARGET) --all --verbose

test: debug
	@echo "  TEST    running smoke tests"
	@./$(TARGET) --acpi --verbose -o /tmp/abyss_test 2>&1 | head -50
	@test -f /tmp/abyss_test/report.json && echo "  PASS    report.json exists" || echo "  FAIL    report.json missing"
	@test -f /tmp/abyss_test/report.html && echo "  PASS    report.html exists" || echo "  FAIL    report.html missing"

format:
	@echo "  FMT     clang-format (if available)"
	@command -v clang-format >/dev/null 2>&1 && \
		clang-format -i $(SRCS) $(HDRS) || \
		echo "  SKIP    clang-format not installed"

analyze:
	@echo "  ANALYZE cppcheck (if available)"
	@command -v cppcheck >/dev/null 2>&1 && \
		cppcheck --enable=warning,style,performance,portability \
			--inline-suppr --quiet $(SRCS) || \
		echo "  SKIP    cppcheck not installed"

valgrind: debug
	@echo "  VALGRIND"
	@command -v valgrind >/dev/null 2>&1 && \
		valgrind --leak-check=full --show-leak-kinds=all \
			--track-origins=yes --error-exitcode=1 \
			./$(TARGET) --acpi --verbose 2>&1 | tail -30 || \
		echo "  SKIP    valgrind not installed"

help:
	@echo "abyss v$(VERSION) -- build targets"
	@echo ""
	@echo "  make            build release binary (default)"
	@echo "  make debug      build with -g3 -O0 and DEBUG defined"
	@echo "  make sanitize   build with ASan + UBSan"
	@echo "  make clean      remove build artifacts"
	@echo "  make install    install to $(BINDIR)"
	@echo "  make uninstall  remove installed binary"
	@echo "  make run        build debug and run --all"
	@echo "  make test       run smoke tests"
	@echo "  make format     format sources with clang-format"
	@echo "  make analyze    static analysis with cppcheck"
	@echo "  make valgrind   run under valgrind"
	@echo "  make help       show this message"
	@echo ""
	@echo "Variables:"
	@echo "  CC=$(CC)"
	@echo "  CFLAGS=$(CFLAGS)"
	@echo "  PREFIX=$(PREFIX)"