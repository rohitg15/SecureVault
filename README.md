SecureVault is a tool that helps protect and store secrets of any size. It may also be used to protect arbitrary files of the user's choice.


##Building

~~~
mkdir build
cd build
cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib/ ..
make
~~~

##Running

~~~
cd build && make test
~~~

or

~~~
build/test/testfoo/testfoo
~~~
