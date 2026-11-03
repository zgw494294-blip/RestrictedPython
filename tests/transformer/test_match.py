"""Tests for the guarded structural pattern matching (``match``/``case``)."""

import ast
from collections import UserDict
from collections import deque

import pytest

from RestrictedPython import compile_restricted
from RestrictedPython import compile_restricted_exec
from RestrictedPython import compile_restricted_function
from RestrictedPython.Guards import guarded_match
from RestrictedPython.Guards import guarded_unpack_sequence
from RestrictedPython.Guards import safe_globals


def _match_globals(_getitem_=lambda ob, key: ob[key],
                   _getiter_=lambda ob: ob,
                   _getattr_=getattr):
    glb = dict(safe_globals)
    glb['_getitem_'] = _getitem_
    glb['_getiter_'] = _getiter_
    glb['_getattr_'] = _getattr_
    return glb


def _run(source, **extra):
    result = compile_restricted_exec(source)
    assert result.errors == (), result.errors
    glb = _match_globals(**extra)
    exec(result.code, glb)
    return glb


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

ALL_PATTERNS = """
def classify(event):
    match event:
        case None | True | False:
            return 'singleton'
        case 0 | -1 | 1.5 | 's' | b'b' | Color.RED:
            return 'value'
        case (1, second):
            return ('pair', second)
        case [first, *middle, last] as whole:
            return ('sequence', first, middle, last, whole is event)
        case {'type': 'click', 'x': x, 'y': y, **rest}:
            return ('mapping', x, y, rest)
        case [{'nested': value}]:
            return ('nested', value)
        case captured:
            return ('capture', captured)
"""


def test_match_all_patterns_compile_clean():
    result = compile_restricted_exec(ALL_PATTERNS)
    assert result.errors == ()
    assert result.warnings == []


def test_match_dotted_constants_track_used_names():
    result = compile_restricted_exec(
        "match event:\n"
        "    case Color.RED | shape.CIRCLE:\n"
        "        pass\n")
    assert result.errors == ()
    assert 'Color' in result.used_names
    assert 'shape' in result.used_names


def test_match_class_pattern_rejected():
    result = compile_restricted_exec(
        "match event:\n"
        "    case Point(x, y):\n"
        "        pass\n")
    assert result.errors
    assert 'Class patterns are not allowed.' in result.errors[0]


def test_match_nested_class_pattern_rejected():
    result = compile_restricted_exec(
        "match event:\n"
        "    case [Point(x)]:\n"
        "        pass\n")
    assert result.errors
    assert 'Class patterns are not allowed.' in result.errors[0]
    result = compile_restricted_exec(
        "match event:\n"
        "    case {'p': Point(x)}:\n"
        "        pass\n")
    assert result.errors
    assert 'Class patterns are not allowed.' in result.errors[0]


@pytest.mark.parametrize('source,message', [
    # capture / wildcard / star / rest / as all share the name checks
    ("match x:\n    case _secret:\n        pass\n",
     'invalid variable name'),
    ("match x:\n    case [*_secret]:\n        pass\n",
     'invalid variable name'),
    ("match x:\n    case {**_secret}:\n        pass\n",
     'invalid variable name'),
    ("match x:\n    case 1 as _secret:\n        pass\n",
     'invalid variable name'),
    ("match x:\n    case printed:\n        pass\n",
     'reserved name'),
    # duplicate captures
    ("match x:\n    case [a, a]:\n        pass\n",
     "multiple assignments to name 'a' in pattern"),
    ("match x:\n    case [a] as a:\n        pass\n",
     "multiple assignments to name 'a' in pattern"),
    ("match x:\n    case {'a': a, **a}:\n        pass\n",
     "multiple assignments to name 'a' in pattern"),
    # or patterns bind different names
    ("match x:\n    case [a] | [a, b]:\n        pass\n",
     'alternative patterns bind different names'),
    # irrefutable patterns have to be the last alternative
    ("match x:\n"
     "    case a:\n        pass\n"
     "    case 1:\n        pass\n",
     "name capture 'a' makes remaining patterns unreachable"),
    ("match x:\n"
     "    case _:\n        pass\n"
     "    case 1:\n        pass\n",
     'wildcard makes remaining patterns unreachable'),
    ("match x:\n"
     "    case 1 | a:\n        pass\n"
     "    case 2:\n        pass\n",
     "name capture 'a' makes remaining patterns unreachable"),
    # only one star in a sequence
    ("match x:\n    case [*a, *b]:\n        pass\n",
     'multiple starred names in sequence pattern'),
    # duplicate constant mapping keys
    ("match x:\n    case {'a': 1, 'a': 2}:\n        pass\n",
     "mapping pattern checks duplicate key ('a')"),
])
def test_match_compile_errors(source, message):
    result = compile_restricted_exec(source)
    assert result.errors
    assert message in result.errors[0]


def test_match_star_wildcard_and_double_star_compile():
    result = compile_restricted_exec(
        "match x:\n"
        "    case [*_]:\n        pass\n"
        "    case {**rest}:\n        pass\n")
    assert result.errors == (), result.errors


def test_match_policy_none_is_unrestricted():
    glb = {}
    code = compile_restricted(
        "match 1:\n"
        "    case _secret:\n"
        "        result = _secret\n",
        policy=None)
    exec(code, glb)
    assert glb['result'] == 1


def test_match_compile_restricted_function():
    result = compile_restricted_function(
        'event',
        "match event:\n"
        "    case {'type': t}:\n"
        "        return t\n",
        'handle')
    assert result.errors == (), result.errors
    glb = _match_globals()
    exec(result.code, glb)
    assert glb['handle']({'type': 'click'}) == 'click'


def test_match_custom_policy_inherits_support():
    from RestrictedPython.transformer import RestrictingNodeTransformer

    class CustomPolicy(RestrictingNodeTransformer):
        pass

    result = compile_restricted_exec(
        "match (1,):\n"
        "    case (a,):\n"
        "        result = a\n", policy=CustomPolicy)
    assert result.errors == (), result.errors
    glb = _match_globals()
    exec(result.code, glb)
    assert glb['result'] == 1


# ---------------------------------------------------------------------------
# Value and singleton patterns
# ---------------------------------------------------------------------------

def test_match_literal_values():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case 1:\n"
        "            return 'int'\n"
        "        case -2:\n"
        "            return 'negative'\n"
        "        case 1.5:\n"
        "            return 'float'\n"
        "        case 's':\n"
        "            return 'str'\n"
        "        case b'b':\n"
        "            return 'bytes'\n"
        "        case (1, 2):\n"
        "            return 'tuple literal'\n"
        "        case _:\n"
        "            return 'other'\n")
    f = glb['f']
    assert f(1) == 'int'
    assert f(-2) == 'negative'
    assert f(1.5) == 'float'
    assert f('s') == 'str'
    assert f(b'b') == 'bytes'
    assert f((1, 2)) == 'tuple literal'
    assert f(3) == 'other'


def test_match_value_equality_matches_python_semantics():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case 1:\n"
        "            return 'one'\n"
        "        case _:\n"
        "            return 'other'\n")
    # Plain ``==`` semantics, like CPython: ``True == 1`` and
    # ``1.0 == 1``.
    assert glb['f'](True) == 'one'
    assert glb['f'](1.0) == 'one'
    assert glb['f'](2) == 'other'


def test_match_singletons_use_identity():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case None:\n"
        "            return 'none'\n"
        "        case True:\n"
        "            return 'true'\n"
        "        case False:\n"
        "            return 'false'\n"
        "        case _:\n"
        "            return 'other'\n")
    f = glb['f']
    assert f(None) == 'none'
    assert f(True) == 'true'
    assert f(False) == 'false'
    assert f(0) == 'other'
    assert f(1) == 'other'


class _Color:
    RED = 'red'


def test_match_dotted_constant_uses_getattr_guard(mocker):
    _getattr_ = mocker.stub()
    _getattr_.side_effect = lambda ob, name: getattr(ob, name)
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case Color.RED:\n"
        "            return 'red'\n"
        "        case _:\n"
        "            return 'other'\n",
        _getattr_=_getattr_)
    glb['Color'] = _Color
    assert glb['f']('red') == 'red'
    _getattr_.assert_called_once_with(_Color, 'RED')
    assert glb['f']('blue') == 'other'


def test_match_value_equality_exception_propagates():
    class Exploding:
        def __eq__(self, other):
            raise RuntimeError('boom')

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case 1:\n"
        "            return 'one'\n"
        "        case _:\n"
        "            return 'other'\n")
    with pytest.raises(RuntimeError):
        glb['f'](Exploding())


# ---------------------------------------------------------------------------
# Captures, wildcard, subjects and guards
# ---------------------------------------------------------------------------

def test_match_capture_keeps_identity_and_is_not_read():
    # The guards must not be invoked for a plain capture/wildcard subject.
    def fail_getitem(ob, key):
        raise AssertionError('unexpected getitem')

    def fail_getiter(ob):
        raise AssertionError('unexpected getiter')

    sentinel = object()
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case captured:\n"
        "            return captured\n",
        _getitem_=fail_getitem, _getiter_=fail_getiter)
    assert glb['f'](sentinel) is sentinel


def test_match_wildcard_does_not_bind():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case _:\n"
        "            return True\n")
    assert glb['f']('anything') is True


def test_match_bindings_visible_after_the_statement():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case (a, b):\n"
        "            total = a + b\n"
        "    return total\n")
    assert glb['f']((2, 3)) == 5


def test_match_subject_evaluated_once():
    glb = _run(
        "calls = []\n"
        "def subject():\n"
        "    calls.append(1)\n"
        "    return (1, 2)\n"
        "match subject():\n"
        "    case (a, b):\n"
        "        result = (a, b)\n")
    assert glb['result'] == (1, 2)
    assert glb['calls'] == [1]


def test_match_subject_attribute_uses_getattr(mocker):
    _getattr_ = mocker.stub()
    _getattr_.side_effect = lambda ob, name: getattr(ob, name)
    glb = _run(
        "def f(event):\n"
        "    match event.kind:\n"
        "        case 'click':\n"
        "            return True\n",
        _getattr_=_getattr_)

    class Event:
        kind = 'click'

    event = Event()
    assert glb['f'](event) is True
    _getattr_.assert_called_once_with(event, 'kind')


def test_match_first_matching_case_wins():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case 1:\n"
        "            return 'first'\n"
        "        case 1:\n"
        "            return 'second'\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f'](1) == 'first'


def test_match_guard_true_and_false():
    glb = _run(
        "def f(v):\n"
        "    match (v,):\n"
        "        case (x,) if x > 10:\n"
        "            return ('big', x)\n"
        "        case (x,) if x == 5:\n"
        "            return ('five', x)\n"
        "        case (x,):\n"
        "            return ('other', x)\n")
    assert glb['f'](20) == ('big', 20)
    assert glb['f'](5) == ('five', 5)
    assert glb['f'](0) == ('other', 0)


def test_match_guard_sees_bindings_and_body_keeps_them():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a} if a > 0:\n"
        "            return a * 2\n"
        "        case _:\n"
        "            return -1\n")
    assert glb['f']({'a': 21}) == 42


def test_match_guard_exception_propagates():
    glb = _run(
        "def f(v):\n"
        "    match (v,):\n"
        "        case (x,) if v['missing']:\n"
        "            return x\n"
        "        case _:\n"
        "            return 'other'\n")
    with pytest.raises(KeyError):
        glb['f']({})


def test_match_no_case_matches_continues():
    glb = _run(
        "trace = []\n"
        "match 99:\n"
        "    case 1:\n"
        "        trace.append('one')\n"
        "trace.append('after')\n")
    assert glb['trace'] == ['after']


def test_match_case_body_with_unpacking_assignment():
    # Case bodies are transformed too, including statements that expand
    # into multiple statements (such as guarded tuple unpacking).
    result = compile_restricted_exec(
        "def f(v):\n"
        "    match v:\n"
        "        case (pair,):\n"
        "            a, b = pair\n"
        "            return a + b\n"
        "        case _:\n"
        "            return 0\n")
    assert result.errors == (), result.errors
    glb = _match_globals()
    glb['_unpack_sequence_'] = guarded_unpack_sequence
    exec(result.code, glb)
    assert glb['f'](((2, 3),)) == 5


def test_match_case_body_with_rejected_statement():
    # Statements inside case bodies that the visitor rejects return no
    # node and are skipped without crashing the transformation.
    result = compile_restricted_exec(
        "def f(v):\n"
        "    match v:\n"
        "        case x:\n"
        "            nonlocal x\n")
    assert result.errors
    assert 'Nonlocal statements are not allowed.' in result.errors[0]


def test_match_module_level():
    glb = _run(
        "match (1, 2):\n"
        "    case (a, b):\n"
        "        result = a + b\n")
    assert glb['result'] == 3


# ---------------------------------------------------------------------------
# as / or patterns
# ---------------------------------------------------------------------------

def test_match_as_binds_subject_identity():
    record = {'nested': [1, 2]}
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'nested': nested} as whole:\n"
        "            return whole is v, nested is v['nested']\n")
    whole_same, nested_same = glb['f'](record)
    assert whole_same is True
    assert nested_same is True


def test_match_as_failure_continues():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case (1, x) as pair:\n"
        "            return pair\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']((2, 3)) == 'other'


def test_match_or_patterns():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case 1 | 2 | 3:\n"
        "            return 'small'\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f'](1) == 'small'
    assert glb['f'](3) == 'small'
    assert glb['f'](4) == 'other'


def test_match_or_with_captures():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [x] | (x,):\n"
        "            return x\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']([7]) == 7
    assert glb['f']((7,)) == 7


def test_match_untried_alternative_constants_not_evaluated():
    accessed = []

    def tracking_getattr(ob, name):
        accessed.append(name)
        return getattr(ob, name)

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case Color.RED:\n"
        "            return 'red'\n"
        "        case Color.NEVER:\n"
        "            return 'never'\n"
        "        case _:\n"
        "            return 'other'\n",
        _getattr_=tracking_getattr)
    glb['Color'] = _Color
    assert glb['f']('red') == 'red'
    assert accessed == ['RED']


def test_match_dotted_constant_getattr_denial_propagates():
    class Denied(Exception):
        pass

    def deny(ob, name):
        raise Denied

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case Color.SECRET:\n"
        "            return 'secret'\n"
        "        case _:\n"
        "            return 'other'\n",
        _getattr_=deny)

    class Color:
        pass

    glb['Color'] = Color
    with pytest.raises(Denied):
        glb['f'](1)


def test_match_subject_exception_propagates():
    glb = _run(
        "def boom():\n"
        "    raise ValueError('boom')\n"
        "def f():\n"
        "    match boom():\n"
        "        case _:\n"
        "            return 1\n")
    with pytest.raises(ValueError):
        glb['f']()


def test_match_unhashable_key_propagates():
    class BadKeys:
        K = ['unhashable']

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {BadKeys.K: x}:\n"
        "            return x\n")
    glb['BadKeys'] = BadKeys
    with pytest.raises(TypeError):
        glb['f']({'other': 0})


# ---------------------------------------------------------------------------
# Sequence patterns
# ---------------------------------------------------------------------------

def test_match_sequence_list_and_tuple():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [a, b]:\n"
        "            return a, b\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']([1, 2]) == (1, 2)
    assert glb['f']((3, 4)) == (3, 4)


def test_match_sequence_wrong_length_continues():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [a]:\n"
        "            return ('one', a)\n"
        "        case [a, b]:\n"
        "            return ('two', a, b)\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']([1]) == ('one', 1)
    assert glb['f']([1, 2]) == ('two', 1, 2)
    assert glb['f']([1, 2, 3]) == 'other'
    assert glb['f']([]) == 'other'


def test_match_sequence_uses_getiter(mocker):
    _getiter_ = mocker.stub()
    _getiter_.side_effect = lambda ob: ob
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [a, b]:\n"
        "            return a, b\n"
        "        case _:\n"
        "            return 'other'\n",
        _getiter_=_getiter_)
    assert glb['f']((1, 2)) == (1, 2)
    _getiter_.assert_called_once_with((1, 2))


def test_match_sequence_getiter_denial_propagates():
    class Denied(Exception):
        pass

    def deny(ob):
        raise Denied

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [a]:\n"
        "            return a\n"
        "        case _:\n"
        "            return 'other'\n",
        _getiter_=deny)
    with pytest.raises(Denied):
        glb['f']([1])


def test_match_nested_sequence_uses_getiter_per_level(mocker):
    calls = []
    _getiter_ = mocker.stub()

    def side_effect(ob):
        calls.append(ob)
        return ob

    _getiter_.side_effect = side_effect
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [a, (b, c)]:\n"
        "            return a, b, c\n"
        "        case _:\n"
        "            return 'other'\n",
        _getiter_=_getiter_)
    assert glb['f']([1, (2, 3)]) == (1, 2, 3)
    assert calls == [[1, (2, 3)], (2, 3)]


@pytest.mark.parametrize('subject', ['ab', b'ab', bytearray(b'ab')])
def test_match_strings_and_bytes_are_not_sequences(subject):
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [a, b]:\n"
        "            return 'sequence'\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f'](subject) == 'other'


def test_match_generic_sequence_recognized():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [a, b]:\n"
        "            return a, b\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f'](deque([5, 6])) == (5, 6)


def test_match_non_sequence_continues():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [a]:\n"
        "            return 'sequence'\n"
        "        case {}:\n"
        "            return 'mapping'\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f'](1) == 'other'
    assert glb['f'](iter([1])) == 'other'


def test_match_empty_sequence():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case []:\n"
        "            return 'empty'\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']([]) == 'empty'
    assert glb['f']([1]) == 'other'


def test_match_star_capture_positions():
    glb = _run(
        "def f(pattern, v):\n"
        "    match (pattern, v):\n"
        "        case ('first', [*head, last]):\n"
        "            return head, last\n"
        "        case ('middle', [first, *mid, last]):\n"
        "            return first, mid, last\n"
        "        case ('last', [first, *tail]):\n"
        "            return first, tail\n"
        "        case ('wild', [first, *_, last]):\n"
        "            return first, last\n")
    f = glb['f']
    assert f('first', [1, 2, 3]) == ([1, 2], 3)
    assert f('middle', [1, 2, 3, 4]) == (1, [2, 3], 4)
    assert f('last', [1, 2, 3]) == (1, [2, 3])
    assert f('wild', [1, 2, 3]) == (1, 3)


def test_match_star_capture_is_fresh_list_and_source_unchanged():
    source = [1, 2, 3, 4]
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [first, *middle, last]:\n"
        "            return middle\n")
    middle = glb['f'](source)
    assert middle == [2, 3]
    middle.append('tampered')
    assert source == [1, 2, 3, 4]


def test_match_star_requires_enough_items():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [a, *b, c]:\n"
        "            return a, b, c\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']([1]) == 'other'
    assert glb['f']([1, 2]) == (1, [], 2)


# ---------------------------------------------------------------------------
# Mapping patterns
# ---------------------------------------------------------------------------

def test_match_mapping_dict():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a, 'b': b}:\n"
        "            return a, b\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']({'a': 1, 'b': 2, 'c': 3}) == (1, 2)


def test_match_mapping_uses_getitem(mocker):
    _getitem_ = mocker.stub()
    _getitem_.side_effect = lambda ob, key: ob[key]
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a}:\n"
        "            return a\n"
        "        case _:\n"
        "            return 'other'\n",
        _getitem_=_getitem_)
    assert glb['f']({'a': 42}) == 42
    _getitem_.assert_called_once_with({'a': 42}, 'a')


def test_match_mapping_missing_key_continues():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a}:\n"
        "            return ('a', a)\n"
        "        case {'b': b}:\n"
        "            return ('b', b)\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']({'b': 2}) == ('b', 2)
    assert glb['f']({'c': 3}) == 'other'


def test_match_mapping_user_dict():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a, **rest}:\n"
        "            return a, rest\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f'](UserDict(a=1, b=2)) == (1, {'b': 2})
    assert glb['f'](UserDict()) == 'other'


def test_match_mapping_user_dict_missing_key_continues():
    # A non dict mapping with enough keys but a plain missing key raises
    # ``KeyError`` in the host guard, which has to be treated as a
    # non-match rather than propagated.
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a}:\n"
        "            return ('a', a)\n"
        "        case {'b': b}:\n"
        "            return ('b', b)\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f'](UserDict({'b': 2})) == ('b', 2)
    assert glb['f'](UserDict({'c': 3})) == 'other'


def test_match_mapping_too_short_does_not_read_items(mocker):
    _getitem_ = mocker.stub()
    _getitem_.side_effect = lambda ob, key: ob[key]
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a, 'b': b}:\n"
        "            return 'match'\n"
        "        case _:\n"
        "            return 'other'\n",
        _getitem_=_getitem_)
    assert glb['f']({'a': 1}) == 'other'
    _getitem_.assert_not_called()


def test_match_mapping_unrelated_fields_not_read_on_mismatch():
    reads = []

    def tracking_getitem(ob, key):
        reads.append(key)
        return ob[key]

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': 1, 'b': b}:\n"
        "            return 'match'\n"
        "        case _:\n"
        "            return 'other'\n",
        _getitem_=tracking_getitem)
    assert glb['f']({'a': 2, 'b': 3}) == 'other'
    assert reads == ['a']


def test_match_mapping_getitem_denial_propagates():
    class Denied(Exception):
        pass

    def deny(ob, key):
        raise Denied

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a}:\n"
        "            return a\n"
        "        case _:\n"
        "            return 'other'\n",
        _getitem_=deny)
    with pytest.raises(Denied):
        glb['f']({'a': 1})


def test_match_mapping_non_keyerror_propagates():
    def fail(ob, key):
        raise RuntimeError('not a missing key')

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a}:\n"
        "            return a\n"
        "        case _:\n"
        "            return 'other'\n",
        _getitem_=fail)
    with pytest.raises(RuntimeError):
        glb['f']({'a': 1})


def test_match_mapping_defaultdict_is_not_mutated():
    from collections import defaultdict
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a}:\n"
        "            return ('a', a)\n"
        "        case _:\n"
        "            return 'other'\n")
    subject = defaultdict(list)
    assert glb['f'](subject) == 'other'
    assert dict(subject) == {}


def test_match_mapping_rest_is_fresh_authorized_dict():
    getitem_calls = []
    getiter_calls = []

    def tracking_getitem(ob, key):
        getitem_calls.append(key)
        return ob[key]

    def tracking_getiter(ob):
        getiter_calls.append(ob)
        return ob

    source = {'a': 1, 'b': 2, 'c': 3}
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a, **rest}:\n"
        "            return a, rest\n",
        _getitem_=tracking_getitem, _getiter_=tracking_getiter)
    a, rest = glb['f'](source)
    assert a == 1
    assert rest == {'b': 2, 'c': 3}
    assert rest is not source
    rest['b'] = 'tampered'
    assert source['b'] == 2
    assert getiter_calls == [source]
    assert sorted(getitem_calls) == ['a', 'b', 'c']


def test_match_mapping_rest_getiter_denial_propagates():
    class Denied(Exception):
        pass

    def deny(ob):
        raise Denied

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'a': a, **rest}:\n"
        "            return rest\n",
        _getiter_=deny)
    with pytest.raises(Denied):
        glb['f']({'a': 1, 'b': 2})


def test_match_mapping_dotted_key(mocker):
    _getattr_ = mocker.stub()
    _getattr_.side_effect = lambda ob, name: getattr(ob, name)
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {Color.RED: value}:\n"
        "            return value\n"
        "        case _:\n"
        "            return 'other'\n",
        _getattr_=_getattr_)
    glb['Color'] = _Color
    assert glb['f']({'red': 7}) == 7
    _getattr_.assert_called_once_with(_Color, 'RED')


def test_match_mapping_non_mapping_continues():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case [x]:\n"
        "            return 'sequence'\n"
        "        case {}:\n"
        "            return 'mapping'\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']([1]) == 'sequence'
    assert glb['f'](1) == 'other'


def test_match_empty_mapping():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {}:\n"
        "            return 'mapping'\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']({}) == 'mapping'
    assert glb['f'](UserDict()) == 'mapping'
    assert glb['f'](1) == 'other'


def test_match_rest_only_pattern():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {**rest}:\n"
        "            return rest\n"
        "        case _:\n"
        "            return 'other'\n")
    assert glb['f']({'a': 1}) == {'a': 1}


def test_match_runtime_duplicate_keys_raise_value_error():
    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {Color.RED: 1, Color.RED: 2}:\n"
        "            return 'match'\n")
    glb['Color'] = _Color
    with pytest.raises(ValueError):
        glb['f']({'red': 1, 'other': 2})


# ---------------------------------------------------------------------------
# Authorized values
# ---------------------------------------------------------------------------

def test_match_captures_use_authorized_values():
    class Wrapper:
        def __init__(self, value):
            self.value = value

    def wrapping_getitem(ob, key):
        value = ob[key]
        if isinstance(value, (list, dict)):
            return value
        return Wrapper(value)

    def wrapping_getiter(ob):
        for value in ob:
            if isinstance(value, (list, dict)):
                yield value
            else:
                yield Wrapper(value)

    glb = _run(
        "def f(v):\n"
        "    match v:\n"
        "        case {'items': [first, *middle, last], 'kind': kind}:\n"
        "            return first, middle, last, kind\n",
        _getitem_=wrapping_getitem, _getiter_=wrapping_getiter)
    first, middle, last, kind = glb['f'](
        {'items': [1, 2, 3], 'kind': 'demo'})
    assert isinstance(first, Wrapper) and first.value == 1
    assert isinstance(last, Wrapper) and last.value == 3
    assert all(isinstance(item, Wrapper) for item in middle)
    assert [item.value for item in middle] == [2]
    assert isinstance(middle, list)
    assert isinstance(kind, Wrapper) and kind.value == 'demo'


# ---------------------------------------------------------------------------
# Runtime helper specs (built by the transformer, checked directly for the
# error branch and for the public default binding)
# ---------------------------------------------------------------------------

def test_safe_globals_provides_default_match_binding():
    assert safe_globals['_match_'] is guarded_match


def test_guarded_match_invalid_spec_raises():
    with pytest.raises(ValueError):
        guarded_match(
            1, ('?',), lambda ob, key: ob[key], lambda ob: ob)


def test_guarded_match_wildcard_and_capture():
    def getitem(ob, key):
        return ob[key]

    def getiter(ob):
        return ob

    assert guarded_match(1, ('W',), getitem, getiter) == {}
    assert guarded_match(1, ('C', 'x'), getitem, getiter) == {'x': 1}


def test_guarded_match_singleton_and_value():
    def getitem(ob, key):
        return ob[key]

    def getiter(ob):
        return ob

    def one():
        return 1

    assert guarded_match(None, ('S', None), getitem, getiter) == {}
    assert guarded_match(1, ('S', None), getitem, getiter) is None
    assert guarded_match(1, ('V', one), getitem, getiter) == {}
    assert guarded_match(2, ('V', one), getitem, getiter) is None


def test_guarded_match_as_and_or():
    def getitem(ob, key):
        return ob[key]

    def getiter(ob):
        return ob

    def one():
        return 1

    def two():
        return 2

    spec_as = ('A', ('S', None), 'x')
    assert guarded_match(None, spec_as, getitem, getiter) == {'x': None}
    assert guarded_match(1, spec_as, getitem, getiter) is None
    spec_or = ('O', (('V', one), ('V', two)))
    assert guarded_match(2, spec_or, getitem, getiter) == {}
    assert guarded_match(3, spec_or, getitem, getiter) is None


# ---------------------------------------------------------------------------
# Crafted AST (the grammar cannot produce all AST shapes, but the transformer
# must not crash on hand built AST passed in by hosts)
# ---------------------------------------------------------------------------

def _function(name, body):
    return ast.FunctionDef(
        name=name,
        args=ast.arguments(
            posonlyargs=[], args=[ast.arg(arg='v')], vararg=None,
            kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=body,
        decorator_list=[],
        returns=None,
        type_comment=None)


def test_match_handles_crafted_ast_patterns():
    # ``MatchAs`` wrapping a pattern without a name and a bare ``MatchStar``
    # are not produced by the parser.
    module = ast.Module(body=[
        _function('f', [
            ast.Match(
                subject=ast.Name(id='v', ctx=ast.Load()),
                cases=[
                    ast.match_case(
                        pattern=ast.MatchAs(
                            pattern=ast.MatchSingleton(value=None),
                            name=None),
                        guard=None,
                        body=[ast.Return(
                            value=ast.Constant(value='singleton'))]),
                ]),
            ast.Return(value=ast.Constant(value='other')),
        ]),
        _function('g', [
            ast.Match(
                subject=ast.Name(id='v', ctx=ast.Load()),
                cases=[
                    ast.match_case(
                        pattern=ast.MatchStar(name=None),
                        guard=None,
                        body=[ast.Return(
                            value=ast.Constant(value='star'))]),
                    ast.match_case(
                        pattern=ast.MatchAs(),
                        guard=None,
                        body=[ast.Return(
                            value=ast.Constant(value='other'))]),
                ]),
        ]),
    ], type_ignores=[])
    ast.fix_missing_locations(module)
    result = compile_restricted_exec(module)
    assert result.errors == (), result.errors
    glb = _match_globals()
    exec(result.code, glb)
    assert glb['f'](None) == 'singleton'
    assert glb['f'](1) == 'other'
    assert glb['g'](1) == 'star'
