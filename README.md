# timplus-smack-tcp-netty
An implementation of a TCP smack connection using the Netty networking framework.

The purpose of this library is for systems that are building bridging services between 
existing implemenations and TIM+ service providers.  In many cases, a bridge service may need to
make hundreds if not thousands of connections to a TIM+ service.  The current TCP smack implemenation
creates at least 1 additional thread per connection which would run the system out
of threading resources.  Using the Netty asncy/non-blocking model, threads can be greatly
reduced and system resources used much more efficiently.
