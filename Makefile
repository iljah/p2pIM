default: all

TESTS=
CLEAN=

include tests/generate1_tests1 tests/server1_tests1

all: $(TESTS)

c: clean
clean:
	rm -f $(TESTS) $(CLEAN) diff.ok generate1.ok server1.ok socat.ok

diff.ok:
	@echo -n 'Checking diff...  ' && diff --help > /dev/null && touch $@ && echo ok

generate1.ok: generate1.py
	@echo -n 'Checking generate1.py...  ' && python $< --help > /dev/null && touch $@ && echo ok

server1.ok: server1.py
	@echo -n 'Checking server1.py...  ' && python $< --help > /dev/null && touch $@ && echo ok

socat.ok:
	@echo -n 'Checking socat...  ' && socat -h > /dev/null && touch $@ && echo ok
