
default: stayinalived config.json

stayinalived: *.go static/*
	go build -race -o $@

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


foo:
	rsync -av --exclude=main.go --exclude=balancer.go --exclude=xvs.go ../../vc5/cmd/*.go .
	rsync -av --delete ../../vc5/cmd/static/ static/
