
PROJECT = xdp_acl

.PHONY: clean $(PROJECT) pub


all: xdp_acl.c main.go
	@go generate && go build

clean:
	@rm -rf *.o *_bpfeb.go *_bpfel.go $(PROJECT)

pub: xdp_acl public acl.json readme.md
	@if [ -d "acl" ]; then \
		rm -rf acl; \
	fi; \
	mkdir acl; \
	cp xdp_acl acl; \
	cp -rf public acl; \
	cp readme.md acl; \
	cp acl.json acl; \
        echo "Pub OK!";
