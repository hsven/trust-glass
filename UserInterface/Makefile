PROG ?= sslecho

all: $(PROG)

# Debug version.
#
$(PROG): Client.cpp

	$(CC) -O0 -g3 -W -Wall -I../../include -L../../ -o $(PROG) Client.cpp -lssl -lcrypto

clean:
	rm -rf $(PROG) *.o *.obj