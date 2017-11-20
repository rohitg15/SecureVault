A sample project illustrating how to perform unit testing with GoogleTest and CMake

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

Refer to [this blog post](http://kaizou.org/2014/11/gtest-cmake/) for a detailed explaination of how it works.
