corpus:
	mkdir /tmp/in && echo "AAA" > /tmp/in/A

run: corpus
	/AFLplusplus/afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzamoto_scenario-http-server

test: corpus
	#!/bin/bash
	(timeout 31s /AFLplusplus/afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzamoto_scenario-http-server | tee stdout.log || exit 1)
	if grep -oP '\b\d+(?= new corpus items found)' stdout.log; then
		echo "Fuzzer is working"
	else 
		echo "Fuzzer does not generate enough testcases"
		exit 1
	fi

[working-directory: '/fuzzamoto']
clean:
	rm -rf /tmp/in && rm -rf /tmp/out && cargo clean
