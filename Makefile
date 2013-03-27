REBAR = ./rebar

default: compile

all: deps compile

compile:
	$(REBAR) compile

test/syslog_header_benchmark.beam: test/syslog_header_benchmark.erl
	erlc -o test test/syslog_header_benchmark.erl

bench: compile test/syslog_header_benchmark.beam
	./test/benchmark

deps:
	$(REBAR) get-deps

clean:
	$(REBAR) clean

distclean: clean 
	$(REBAR) delete-deps

test:
	$(REBAR) skip_deps=true eunit

docs: deps
	$(REBAR) skip_deps=true doc

dialyzer: compile
	@dialyzer -Wno_return -c ebin

.PHONY: all deps test
