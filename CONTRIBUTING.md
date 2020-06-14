If you are reading this then that means you are thinking of contributing to the OpenFIPS201 applet. We couldn't be happier!



#### Code Guidelines

There are a few important points to consider when contributing to OpenFIPS201:

* This is a cryptographic security product first and foremost. This means that great care should be taken when dealing with your usage of cryptographic primitives and algorithms. Keeping things simple, sanitising every input and sticking to well understood implementation principles is the best philosophy here.
* OpenFIPS201 is intended to be as much a reference implementation as it is a production quality product. This is why you'll see a heavy emphasis on comments in the code, many of which directly quote the parts of the standard they implement. Any contributions should provide at least a similar level of intrinsic documentation.
* We are in the process of migrating to the [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html), which will soon be enforced using a GitHub action when any code is pushed. 



#### Copyright

OpenFIPS201 is released entirely under the [MIT license](https://opensource.org/licenses/MIT). Since any contributions accepted into this repository remain the copyright of the author, we consider that by creating a pull request you are giving implicit approval for anything you submit to be released under the same MIT license and free of any other conditions, limitations or fees.

If this isn't the case, then we probably can't accept your contribution, but of course the first thing is to get in touch **before** creating the pull request to chat about it if you are concerned.