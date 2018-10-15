all:
	[ -e test.link ] || ln -sf /etc/passwd test.link
	[ -e test.fifo ] || mkfifo test.fifo
	[ -e test.sock ] || python -c "import socket as s; sock = s.socket(s.AF_UNIX); sock.bind('test.sock')"
	../src/filestat -t csv /etc/passwd /etc test.link test.fifo test.sock /dev/null /dev/disk0
	[ -e test.link ] && rm -f test.link
	[ -e test.fifo ] && rm -f test.fifo
	[ -e test.sock ] && rm -f test.sock

install:

clean:
	rm -rf test.*
