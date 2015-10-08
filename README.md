rust-keepass
============

[![Build Status](https://travis-ci.org/raymontag/rust-keepass.svg?branch=master)](https://travis-ci.org/raymontag/rust-keepass)

Works with nightly only!

Usage
-----

We try to take care that all security related functions are not optimized away by the compiler (see issue #4). However we can not ensure that this really works. If you want to be on the safe side, turn optimization with the opt-level-option off like it is described [here](http://doc.crates.io/manifest.html#the-profile-sections). It is necessary that you do this in the top-level project as dependency options are overwritten!

License
-------

See the [LICENSE](LICENSE.md) file for license rights and limitations (ISC).