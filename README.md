# http1.1

Recon tool for client-side desync recon. Filters a host list down to targets that are HTTP/1.1 only and support keep-alive, which are the two hard requirements for CSD to work against real browser victims.

## Install

```bash
git clone https://github.com/J707-2/http1.1
cd http1.1
chmod +x http1.1.py
cp http1.1.py /usr/local/bin/http1.1
```

Python 3.8+, no external dependencies.

## Usage

First run, set your output directory:

```bash
http1.1 --output ~/path/to/output
```

Then point it at a hosts file:

```bash
http1.1 <name> <hosts.txt>
```

Results go to the output directory under the scan name. H2 hosts are discarded and not written anywhere.

```
--threads N    concurrent threads (default: 30)
--timeout S    socket timeout in seconds (default: 8)
--output PATH  set output base directory
```

## Output

```
[+] target.com        http/1.1  keep-alive
[~] other.com         http/1.1  no keep-alive
[-] google.com        http/2 - skip
[!] dead.com          unreachable
```

keepalive.txt is what you actually care about.
