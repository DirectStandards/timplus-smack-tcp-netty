# timplus-smack-tcp-netty
An implementation of a TCP smack connection using the Netty networking framework.

The purpose of this library is for systems that are building bridging services between 
existing implemenations and TIM+ service providers.  In many cases, a bridge service may need to
make hundreds if not thousands of connections to a TIM+ service.  The current TCP smack implemenation
creates at least 1 additional thread per connection which would run the system out
of threading resources.  Using the Netty asncy/non-blocking model, threads can be greatly
reduced and system resources used much more efficiently.

The number of NIO threads is hard set based on the number of available cores reported by the
system.  Effectively the formula is (cores/2) where cores may includes "virtual"
cores accounted for by hyper threading (many JVMs report double the amount of physical cores because
hyper threading allows for double the amount of threads per physical core).

The connection framework makes a lot of reasonable assumptions and ignores some of the options
available in the Smack TCP configuration builder (such as custom socket factory and SSL context).

