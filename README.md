# wchprog

A python program that downloads firmware of CH55x chips through USB link.

## Installation
needs: [pyusb 1.0](https://walac.github.io/pyusb/)

Under ubuntu:
```
sudo apt-get install python-pip
sudo pip install pyusb
```

## Usage (dumper)
See `dumper.py -h` for full help.

To flash and start after flashing:
```
python dumper.py  -f blink.hex -s 
```
To dump the full memory to a hex file:
```
python dumper.py -d -a
```

WCH forum: http://www.wch.cn/bbs/thread-65023-1.html

##

# MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# Copyright(C) 2017 juliuswwj@gmail.com

## Going further:

Python dumper and programmer

- Documentated flashing [c program](https://www.mikrocontroller.net/attachment/393344/flash.c)
