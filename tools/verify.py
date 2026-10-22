"""Acceptance test for every target.  Usage: python tools/verify.py

Exits 0 only if everything passes.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, '..', 'build')
FLAGS = 0x08000000          # CREATE_NO_WINDOW

ok_all = True


def check(label, cond, detail=''):
    global ok_all
    ok_all = ok_all and cond
    print(f'  [{"PASS" if cond else "FAIL"}] {label}' + (f'  {detail}' if detail else ''))


def run(exe, args=(), data=b'', n=1):
    path = os.path.join(BUILD, exe)
    res = []
    for _ in range(n):
        r = subprocess.run([path, *args], input=data, capture_output=True,
                           timeout=10, creationflags=FLAGS)
        res.append((r.returncode, r.stdout))
    return collections.Counter(res)


def main():
    print('sizes')
    expect = {
        'hello-268.exe': 268,
        'hello-echo-arg.exe': 268,
        'hello-echo-fold.exe': 268,
        'hello-echo-stdin.exe': 295,
    }
    for name, size in expect.items():
        path = os.path.join(BUILD, name)
        actual = os.path.getsize(path) if os.path.exists(path) else -1
        check(f'{name} = {size} B', actual == size, f'actual {actual}')

    print('\nhello-268.exe')
    c = run('hello-268.exe', n=200)
    check('200 runs -> rc=0 + "hello world"', list(c) == [(0, b'hello world')], str(dict(c)))

    print('\nhello-echo-arg.exe  (run from a path without spaces -- see limitation)')
    # A quoted program path (any path containing a space) defeats the simple
    # first-space scan, so copy the exe somewhere space-free for these tests.
    shortdir = os.path.join(tempfile.gettempdir(), 'tiny-pe-268-test')
    os.makedirs(shortdir, exist_ok=True)
    short = os.path.join(shortdir, 'echo.exe')
    shutil.copy(os.path.join(BUILD, 'hello-echo-arg.exe'), short)

    def run_short(args, n=1):
        res = []
        for _ in range(n):
            r = subprocess.run([short, *args], capture_output=True, timeout=10,
                               creationflags=FLAGS)
            res.append((r.returncode, r.stdout))
        return collections.Counter(res)

    for args, want in [(['content'], b'content'),
                       (['Hello-from-cmd'], b'Hello-from-cmd'),
                       (['hello', 'world'], b'hello world'),
                       (['x' * 100], b'x' * 100)]:
        c = run_short(args, n=20)
        check(f'argv {args!r:.30} -> {want[:14]!r}', list(c) == [(0, want)], str(dict(c))[:60])
    c = run_short([], n=10)
    check('no args -> empty output, rc=0', list(c) == [(0, b'')], str(dict(c)))
    # Windows renders an empty argument as two quote characters; echoing that
    # verbatim is the correct behaviour for a plain `echo`.
    c = run_short([''], n=10)
    check('empty arg -> echoes the literal ""', list(c) == [(0, b'""')], str(dict(c)))

    print('\nhello-echo-fold.exe (stdin filter)')
    cases = [
        ('empty', b'', b''),
        ('127 B', bytes(range(1, 128)), bytes(range(1, 128))),
        ('binary with NUL', b'a\x00b\x00c', b'a\x00b\x00c'),
        ('CRLF passthrough', b'l1\r\nl2\r\n', b'l1\r\nl2\r\n'),
        ('200 B -> truncated to 127', b'y' * 200, b'y' * 127),
        ('3000 B -> truncated to 127', b'z' * 3000, b'z' * 127),
    ]
    for name, data, want in cases:
        c = run('hello-echo-fold.exe', data=data)
        got = list(c)[0] if len(c) == 1 else None
        check(name, got == (0, want), str(dict(c))[:70])
    c = run('hello-echo-fold.exe', data=b'hello world' * 5, n=100)
    check('100 runs echo 55 B', list(c) == [(0, b'hello world' * 5)], str(dict(c))[:70])

    print('\nhello-echo-stdin.exe (contiguous, over budget; reads up to 2047)')
    c = run('hello-echo-stdin.exe', data=b'hello world', n=20)
    check('20 runs echo', list(c) == [(0, b'hello world')], str(dict(c)))
    c = run('hello-echo-stdin.exe', data=b'q' * 2047)
    check('2047 B passthrough', list(c) == [(0, b'q' * 2047)], str(list(c)[0][1][:20]))
    c = run('hello-echo-stdin.exe', data=b'q' * 3000)
    check('3000 B -> truncated to 2047', list(c) == [(0, b'q' * 2047)], '')

    print('\nredirect via cmd')
    tmp = os.path.join(BUILD, '_r.txt')
    subprocess.run(['cmd', '/c', 'hello-268.exe > _r.txt'], cwd=BUILD, check=False)
    data = open(tmp, 'rb').read() if os.path.exists(tmp) else b'<missing>'
    if os.path.exists(tmp):
        os.remove(tmp)
    check('file gets exactly 11 bytes, no newline', data == b'hello world', repr(data))

    print('\nRESULT:', 'ALL PASS' if ok_all else 'FAILURES PRESENT')
    return 0 if ok_all else 1


if __name__ == '__main__':
    sys.exit(main())
