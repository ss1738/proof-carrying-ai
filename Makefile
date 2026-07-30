.PHONY: install test verify serve bench build clean

install:            ## install the pcai package (editable) + dev extras
	pip install -e . build twine

test:               ## run the pcai library + service + audit tests
	python3 tests/test_pcai.py && python3 tests/test_server.py && python3 tests/test_audit.py

verify:             ## run the FULL suite (Coq proofs + all demos + on-chain forge tests)
	./verify.sh

serve:              ## run the HTTP service on :8787
	python3 -m pcai.cli serve

bench:              ## measure issue/verify time + certificate size for both backends
	python3 -m pcai.cli bench -n 10

build:              ## build the wheel + sdist and validate
	python3 -m build && twine check dist/*

clean:
	rm -rf build dist *.egg-info pcai/__pycache__ tests/__pycache__ coq/*.vo coq/*.glob coq/.*.aux
