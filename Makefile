BINARY  := windroute
PREFIX  ?= /usr/local

.PHONY: build install uninstall vet clean

build:
	go build -o $(BINARY) .

install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)

vet:
	gofmt -l .
	go vet ./...

clean:
	rm -f $(BINARY)
