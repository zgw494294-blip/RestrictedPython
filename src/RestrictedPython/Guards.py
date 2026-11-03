##############################################################################
#
# Copyright (c) 2002 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################

# This tiny set of safe builtins is extended by users of the module.
# AccessControl.ZopeGuards contains a large set of wrappers for builtins.
# DocumentTemplate.DT_UTil contains a few.

import builtins
import collections.abc
import string
import typing

from RestrictedPython.transformer import INSPECT_ATTRIBUTES


safe_builtins = {}

_safe_names = [
    '__build_class__',
    'None',
    'False',
    'True',
    'Ellipsis',
    'abs',
    'bool',
    'bytes',
    'callable',
    'chr',
    'complex',
    'divmod',
    'float',
    'hash',
    'hex',
    'id',
    'int',
    'isinstance',
    'issubclass',
    'len',
    'oct',
    'ord',
    'pow',
    'range',
    'repr',
    'round',
    'slice',
    'sorted',
    'str',
    'tuple',
    'zip'
]

_safe_exceptions = [
    'ArithmeticError',
    'AssertionError',
    'AttributeError',
    'BaseException',
    'BufferError',
    'BytesWarning',
    'DeprecationWarning',
    'EOFError',
    'EnvironmentError',
    'Exception',
    'FloatingPointError',
    'FutureWarning',
    'GeneratorExit',
    'IOError',
    'ImportError',
    'ImportWarning',
    'IndentationError',
    'IndexError',
    'KeyError',
    'KeyboardInterrupt',
    'LookupError',
    'MemoryError',
    'NameError',
    'NotImplementedError',
    'OSError',
    'OverflowError',
    'PendingDeprecationWarning',
    'ReferenceError',
    'RuntimeError',
    'RuntimeWarning',
    'StopIteration',
    'SyntaxError',
    'SyntaxWarning',
    'SystemError',
    'SystemExit',
    'TabError',
    'TypeError',
    'UnboundLocalError',
    'UnicodeDecodeError',
    'UnicodeEncodeError',
    'UnicodeError',
    'UnicodeTranslateError',
    'UnicodeWarning',
    'UserWarning',
    'ValueError',
    'Warning',
    'ZeroDivisionError',
]

for name in _safe_names:
    safe_builtins[name] = getattr(builtins, name)

for name in _safe_exceptions:
    safe_builtins[name] = getattr(builtins, name)


# Wrappers provided by this module:
# delattr
# setattr

# Wrappers provided by ZopeGuards:
# __import__
# apply
# dict
# enumerate
# filter
# getattr
# hasattr
# iter
# list
# map
# max
# min
# sum
# all
# any

# Builtins that are intentionally disabled
# compile   - don't let them produce new code
# dir       - a general purpose introspector, probably hard to wrap
# execfile  - no direct I/O
# file      - no direct I/O
# globals   - uncontrolled namespace access
# input     - no direct I/O
# locals    - uncontrolled namespace access
# open      - no direct I/O
# raw_input - no direct I/O
# vars      - uncontrolled namespace access

# There are several strings that describe Python.  I think there's no
# point to including these, although they are obviously safe:
# copyright, credits, exit, help, license, quit

# Not provided anywhere.  Do something about these?  Several are
# related to new-style classes, which we are too scared of to support
# <0.3 wink>.  coerce, buffer, and reload are esoteric enough that no
# one should care.

# buffer
# bytearray
# classmethod
# coerce
# eval
# intern
# memoryview
# object
# property
# reload
# staticmethod
# super
# type


def _write_wrapper():
    # Construct the write wrapper class
    def _handler(secattr, error_msg):
        # Make a class method.
        def handler(self, *args):
            try:
                f = getattr(self.ob, secattr)
            except AttributeError:
                raise TypeError(error_msg)
            f(*args)
        return handler

    class Wrapper:
        def __init__(self, ob):
            self.__dict__['ob'] = ob

        __setitem__ = _handler(
            '__guarded_setitem__',
            'object does not support item or slice assignment')

        __delitem__ = _handler(
            '__guarded_delitem__',
            'object does not support item or slice assignment')

        __setattr__ = _handler(
            '__guarded_setattr__',
            'attribute-less object (assign or del)')

        __delattr__ = _handler(
            '__guarded_delattr__',
            'attribute-less object (assign or del)')
    return Wrapper


def _full_write_guard():
    # Nested scope abuse!
    # safetypes and Wrapper variables are used by guard()
    safetypes = {dict, list}
    Wrapper = _write_wrapper()

    def guard(ob):
        # Don't bother wrapping simple types, or objects that claim to
        # handle their own write security.
        if type(ob) in safetypes or hasattr(ob, '_guarded_writes'):
            return ob
        # Hand the object to the Wrapper instance, then return the instance.
        return Wrapper(ob)
    return guard


full_write_guard = _full_write_guard()  # type: ignore[no-untyped-call]


def guarded_setattr(object, name, value):
    setattr(full_write_guard(object), name, value)


safe_builtins['setattr'] = guarded_setattr


def guarded_delattr(object, name):
    delattr(full_write_guard(object), name)


safe_builtins['delattr'] = guarded_delattr


raise_ = object()
_FORMATTER_UNSAFE_METHODS = frozenset(('format', 'get_field', 'get_value',
                                       'vformat'))


def safer_getattr(object, name, default=None, getattr=getattr):
    """Getattr implementation which prevents using format on string objects.

    format() is considered harmful:
    http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/

    """
    if type(name) is not str:
        raise TypeError('type(name) must be str')
    if name in ('format', 'format_map') and (
            isinstance(object, str) or
            (isinstance(object, type) and issubclass(object, str))):
        raise NotImplementedError(
            'Using the format*() methods of `str` is not safe')
    if object is string and name == 'Formatter':
        raise NotImplementedError('string.Formatter is not safe')
    if name in _FORMATTER_UNSAFE_METHODS and (
            isinstance(object, string.Formatter) or
            (isinstance(object, type) and
             issubclass(object, string.Formatter))):
        raise NotImplementedError(
            'Using string.Formatter methods is not safe')
    if name in INSPECT_ATTRIBUTES:
        raise AttributeError(
            f'"{name}" is a restricted name,'
            ' that is forbidden to access in RestrictedPython.')
    if name.startswith('_'):
        raise AttributeError(
            '"{name}" is an invalid attribute name because it '
            'starts with "_"'.format(name=name)
        )
    args = (object, name) + (() if default is raise_ else (default,))
    return getattr(*args)


safe_builtins['_getattr_'] = safer_getattr


def safer_getattr_raise(object, name, default=raise_):
    """like ``safer_getattr`` but raising ``AttributeError`` if failing."""
    return safer_getattr(object, name, default)


def guarded_iter_unpack_sequence(it, spec, _getiter_):
    """Protect sequence unpacking of targets in a 'for loop'.

    The target of a for loop could be a sequence.
    For example "for a, b in it"
    => Each object from the iterator needs guarded sequence unpacking.
    """
    # The iteration itself needs to be protected as well.
    for ob in _getiter_(it):
        yield guarded_unpack_sequence(ob, spec, _getiter_)


def guarded_unpack_sequence(it, spec, _getiter_):
    """Protect nested sequence unpacking.

    Protect the unpacking of 'it' by wrapping it with '_getiter_'.
    Furthermore for each child element, defined by spec,
    guarded_unpack_sequence is called again.

    Have a look at transformer.py 'gen_unpack_spec' for a more detailed
    explanation.
    """
    # Do the guarded unpacking of the sequence.
    ret = list(_getiter_(it))

    # If the sequence is shorter then expected the interpreter will raise
    # 'ValueError: need more than X value to unpack' anyway
    # => No childs are unpacked => nothing to protect.
    if len(ret) < spec['min_len']:
        return ret

    # For all child elements do the guarded unpacking again.
    for (idx, child_spec) in spec['childs']:
        ret[idx] = guarded_unpack_sequence(ret[idx], child_spec, _getiter_)

    return ret


# PEP 634 (structural pattern matching) support.
#
# The RestrictedPython transformer compiles every ``match`` statement into a
# call to ``guarded_match`` (bound to the ``_match_`` name in ``safe_globals``)
# passing a pattern specification that it builds itself from trusted AST.
#
# Pattern specs are plain tuples where the first element is a tag string:
#
# ('W',)                      wildcard pattern (``_``)
# ('C', name)                 capture pattern (a bare name)
# ('S', value)                singleton pattern (``None``/``True``/``False``)
# ('V', get_value)            value pattern (literal or dotted name);
#                             ``get_value`` is a zero argument callable that
#                             evaluates the (already guarded) value expression
# ('A', spec, name)           ``as`` pattern
# ('O', (spec, ...))          ``|`` (or) pattern
# ('L', (spec, ...), star, name)  sequence pattern; ``star`` is the index of
#                             the ``*name`` entry or ``-1`` and ``name`` is the
#                             star target or ``None`` (``*_``)
# ('M', ((get_key, spec), ...), name)  mapping pattern; ``name`` is the
#                             ``**name`` target or ``None``
#
# ``guarded_match`` returns a new dict with the names captured by a successful
# match (the values in it are always the objects returned by the host guards)
# and ``None`` when the pattern does not match.  Exceptions raised by guards
# or by the matched objects are never turned into a non-match, except for a
# plain missing mapping key (``KeyError``).

_MATCH_MISSING = object()


def _guarded_match_sequence(
        subject: typing.Any,
        subspecs: tuple[typing.Any, ...],
        star_index: int,
        star_name: str | None,
        _getitem_: typing.Any,
        _getiter_: typing.Any) -> dict[str, typing.Any] | None:
    # Strings and byte strings are never sequence pattern subjects, even
    # though they are registered as ``collections.abc.Sequence``.
    if isinstance(subject, (str, bytes, bytearray)):
        return None
    if not isinstance(subject, collections.abc.Sequence):
        return None

    # Sequence destructuring always goes through the host ``_getiter_``
    # guard, like the byte code generated by CPython itself.
    items = list(_getiter_(subject))
    total = len(items)
    count = len(subspecs)
    if star_index < 0:
        if total != count:
            return None
    elif total < count:
        return None

    bindings: dict[str, typing.Any] = {}
    tail = count - star_index
    for index, subspec in enumerate(subspecs):
        if star_index < 0 or index < star_index:
            element = items[index]
        else:
            element = items[total - tail + (index - star_index)]
        captured = guarded_match(element, subspec, _getitem_, _getiter_)
        if captured is None:
            return None
        bindings.update(captured)

    if star_name is not None:
        # The star capture is always a fresh list and keeps the authorized
        # elements without touching the source sequence.  A star name
        # implies a star pattern, so ``star_index`` is non-negative here.
        bindings[star_name] = list(items[star_index:total - tail])
    return bindings


def _guarded_mapping_value(
        subject: typing.Any,
        key: typing.Any,
        _getitem_: typing.Any) -> typing.Any:
    # Look up a single mapping key without mutating the source.
    if isinstance(subject, dict):
        # Use the C level containment check so ``dict`` subclasses with
        # ``__missing__`` (e.g. ``collections.defaultdict``) neither create
        # missing keys nor return manufactured defaults.  The value itself
        # is still read through the host guard.
        if dict.__contains__(subject, key):
            return _getitem_(subject, key)
        return _MATCH_MISSING
    try:
        return _getitem_(subject, key)
    except KeyError:
        # A plain missing key is a non-match; every other exception (in
        # particular permission denials) is propagated by the caller.
        return _MATCH_MISSING


def _guarded_match_mapping(
        subject: typing.Any,
        entries: tuple[tuple[typing.Any, ...], ...],
        rest_name: str | None,
        _getitem_: typing.Any,
        _getiter_: typing.Any) -> dict[str, typing.Any] | None:
    if not isinstance(subject, collections.abc.Mapping):
        return None

    required = len(entries)
    if required:
        # Like CPython, mappings with fewer keys than the pattern checks
        # for are rejected before any item is read.
        if len(subject) < required:
            return None

    bindings: dict[str, typing.Any] = {}
    seen: set[typing.Any] = set()
    for get_key, subspec in entries:
        key = get_key()
        if key in seen:
            raise ValueError(
                'mapping pattern checks duplicate key ({0!r})'.format(key))
        seen.add(key)
        value = _guarded_mapping_value(subject, key, _getitem_)
        if value is _MATCH_MISSING:
            return None
        captured = guarded_match(value, subspec, _getitem_, _getiter_)
        if captured is None:
            return None
        bindings.update(captured)

    if rest_name is not None:
        # The rest is a fresh dict; its values are read through the host
        # ``_getitem_`` guard and the source mapping is never modified.
        rest: dict[str, typing.Any] = {}
        for key in _getiter_(subject):
            if key not in seen:
                rest[key] = _getitem_(subject, key)
        bindings[rest_name] = rest
    return bindings


def guarded_match(
        subject: typing.Any,
        spec: tuple[typing.Any, ...],
        _getitem_: typing.Any,
        _getiter_: typing.Any) -> dict[str, typing.Any] | None:
    """Match ``subject`` against a trusted pattern ``spec``.

    ``spec`` is built by the RestrictedPython transformer; it is not user
    data.  The host guards ``_getitem_`` and ``_getiter_`` are the same
    callables used for subscripting and iteration elsewhere.

    Returns a dict of captured names on a successful match and ``None`` on
    a non-match.  Guard exceptions and arbitrary expression exceptions are
    propagated instead of being swallowed.
    """
    kind = spec[0]
    if kind == 'W':
        return {}
    if kind == 'C':
        return {spec[1]: subject}
    if kind == 'S':
        if subject is spec[1]:
            return {}
        return None
    if kind == 'V':
        if subject == spec[1]():
            return {}
        return None
    if kind == 'A':
        bindings = guarded_match(subject, spec[1], _getitem_, _getiter_)
        if bindings is None:
            return None
        # ``as`` keeps the identity of the authorized subject.
        bindings[spec[2]] = subject
        return bindings
    if kind == 'O':
        for alternative in spec[1]:
            bindings = guarded_match(
                subject, alternative, _getitem_, _getiter_)
            if bindings is not None:
                return bindings
        return None
    if kind == 'L':
        return _guarded_match_sequence(
            subject, spec[1], spec[2], spec[3], _getitem_, _getiter_)
    if kind == 'M':
        return _guarded_match_mapping(
            subject, spec[1], spec[2], _getitem_, _getiter_)
    raise ValueError(
        'Invalid match pattern specification: {0!r}'.format(spec))


safe_globals: dict[str, typing.Any] = {'__builtins__': safe_builtins}

# Default binding of the match statement helper.  Hosts copy ``safe_globals``
# (as usual) and still provide the ``_getitem_``, ``_getiter_`` and
# ``_getattr_`` guards themselves.
safe_globals['_match_'] = guarded_match
