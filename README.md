##What is it

 - A plugin for IDA Pro 6.1 and higher (and lower?)
 - A way of making almost-arbitrary changes to an executable when run under a debugger -- even changes that don't fit
 - A portmanteau of "reverse-engineering" and "reprogram"

##Installation

Drag the compiled plugin into the IDA "plugins" directory

##Usage

1. Select the region of code you wish to replace, and run REProgram from the Plugins menu or press Alt+F2.
2.In the prompt that pops up, enter the (possibly empty) code that you wish to run instead of the
selected code.
3. To return the region to normal, place your cursor anywhere
within the reprogrammed region and run the plugin again.

A list of all reprogrammed regions is available under the View menu.

##What's Possible


REProgram has two modes of working. If the assembly you type in is not
larger than the original selection, it will behave essentially the same as
if you patched the original executable. When you run the program in the
debugger, REProgram will replace the code in the selection with the
provided code, and fill in any remaining space with NOPs. As a bonus,
using REProgram to modify data segments also works in this case.

If the assembly you type in is larger than the original selection, when
control reaches a reprogrammed region, REProgram will place as many
instructions in the region as it can, and run control through that space
over and over until all the desired instructions have been executed
control passes outside of the region. In this case, jumps to the inside of
the reprogrammed region are not guaranteed to work, although jumps from
the region to the outside are. Note that, as REProgram uses breakpoints to
implement this behavior, focus will return to IDA every time a region
reprogrammed in this manner is hit; minimizing IDA is recommended.

##What's Not

Only x86 is supported. REProgram uses IDA's onboard assembler, and suffers
from all its shortcomings. One workaround is to use the db directive to
specify an instruction in raw machine language

REProgram cannot handle the case where there is an instruction larger than
the reprogrammed region it is meant to fit in; this can typically be
overcome just be widening the region to include adjacent instructions and
adding them to the reprogramming code.

History
#######

REProgram is a successor to nopper, which simulated nopping out code using breakpoints. nopper (and some nifty screenshots) are available at http://code.google.com/p/nopper/

REProgram was entered in the 2011 Hex-Rays Plugin Contest: http://www.hex-rays.com/contests/2011/index.shtml