# user must be isucon
export PATH=/usr/local/bin:/home/isucon/.local/ruby/bin:/home/isucon/.local/node/bin:/home/isucon/.local/python3/bin:/home/isucon/.local/perl/bin:/home/isucon/.local/php/bin:/home/isucon/.local/php/sbin:/home/isucon/.local/go/bin:/home/isucon/.local/scala/bin:$PATH
export GOROOT=/home/isucon/.local/go
export GOPATH=/home/isucon/webapp/go
cd webapp/golang
go get "github.com/gorilla/context"
go get "github.com/gorilla/mux"
go get "github.com/gorilla/sessions"
go get  "github.com/lib/pq"
go build -o app
cp app ~/webapp/golang/app
