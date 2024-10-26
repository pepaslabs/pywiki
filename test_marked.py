#!/usr/bin/env python2

import subprocess

raw_content = """
This is a Markdown test.

Here's a list:
- an item
- another item
  - a nested item

Here's a [link](http://www.google.com)

Here is some code:

```
#!/bin/bash

echo foo
```
"""

#cmd_fpath = './markedz'
cmd_fpath = '/bin/false'
p = subprocess.Popen([cmd_fpath], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
stdout, stderr = p.communicate(raw_content)
print stdout
print stderr
exit_code = p.wait()
print exit_code
