
default: stayinalived config.json

stayinalived: *.go
	go build -o $@

# avoid clobbering an existing config file when make is run with -B
config.yaml:
	if [ ! -e $@ ]; then ./config.pl -x >$@; fi

config.json: config.pl config.yaml
	./config.pl -n config.yaml >$@- && mv $@- $@

clean:
	rm -f stayinalived config.json

# need to pass a hook to git
pre-commit:
	if grep '^replace' go.mod; then false; fi


sync:
	cp ../../vc5/cmd/config.pl .
	rsync -av --exclude=main.go --exclude=balancer.go --exclude=xvs.go ../../vc5/cmd/*.go .
	rsync -av --delete ../../vc5/cmd/static/ static/
