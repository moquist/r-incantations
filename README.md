# r-incantations

# BEWARE: user.clj #
Some people don't like the presence of a user.clj. If you're one of those people, you know what I mean. if you're not, then don't worry about it and carry on. ;)

This is a loose and currently undocumented collection of code bits written while
reading [Data-Driven Security, by Jacobs and
Rudis](http://www.amazon.com/Data-Driven-Security-Analysis-Visualization-Dashboards/dp/1118793722).

Various bits of this code currently assume you have downloaded the
code and data files for the book and placed them in this repo's top
directory under book-data. If you've got /bin/sh, curl, and unzip (or
you aren't sure), you can execute the '''get-book-data.sh''' script to
do this automatically.

Generally speaking, on Linux or Mac OSX you should be able to do this:
'''bash
sh get-book-data.sh
'''

The book uses R and the Pandas Python library, and I want to learn to use
the Clojure Incanter library in parallel.

This is currently incomplete, because I'm only in chapter 5.

Hopefully, someday, I'll have a chance to finish this (whatever that means!),
clean it all up, and add some mo/better documentation.

## License

Copyright © 2014 Matt Oquist <moquist@majen.net>

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
