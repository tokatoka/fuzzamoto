corpus:
        rm -rf /tmp/in && mkdir /tmp/in && echo "AAA" > /tmp/in/A

run: corpus
        /AFLplusplus/afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzamoto_scenario-http-server

test: corpus
        #!/bin/bash
        timeout 30s sh -c 'AFL_NO_UI=1 /AFLplusplus/afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzamoto_scenario-http-server > /dev/null'
        # sleep until stat file is updated
        sleep 5
        count=$(cat /tmp/out/default/fuzzer_stats | grep "corpus_count"| grep -o '[0-9]\+')
        count=${count:-0}
        if [ "$count" -gt 5 ]; then
            echo "Fuzzer is working (new corpus items: $count)"
        else
            echo $count
            cat /tmp/out/default/fuzzer_stats
            echo "Fuzzer does not generate enough testcases (new corpus items: $count)"
            exit 1
        fi

[working-directory: '/fuzzamoto']
clean:
        rm -rf /tmp/in && rm -rf /tmp/out && cargo clean