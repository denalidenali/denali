CC=gcc
CFLAGS+=-c -g -Wall -O3 -DOSX  -Wundef -Wstrict-prototypes -Wuninitialized -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration
INC  += -I$(INCDIR)
LDFLAGS+=  -lpcap  -lm -lz -lcrypto

TARGET =injector
SRCDIR = src
OBJDIR = obj
BINDIR = bin
INCLUDES = $(wildcard include/*.h)
INCDIR = ./include

SOURCES= $(wildcard $(SRCDIR)/*.c)
OBJECTS= $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
EXECUTABLE=meddler

$(BINDIR)/$(TARGET):$(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS)  -o $@ -lpcap -lcrypto -lm -lz
	@echo "Built the binary"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@
	@echo "compiled successfully"

clean:
	rm $(OBJDIR)/*.o $(BINDIR)/injector
