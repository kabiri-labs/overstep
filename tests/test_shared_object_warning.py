"""Two subjects holding the same object are never probed against each other, and it is said.

`validate` already warned when *every* subject resolved to one object: no
cross-owner probe can exist at all. The partial case was silent. With alice
and bob on one id and root on another, the alice-to-bob probe is dropped as a
repeat of alice's own request and replaced by a probe at root's object - so
the resource counts as probed and the plan looks full, while the two peers the
matrix was written to tell apart never meet.
"""
from overstep.matrix import Matrix, Severity
from overstep.planner import plan


def _matrix(objects) -> Matrix:
    return Matrix(
        modules={"rest": {"base_url": "http://t"}},
        roles=["user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a"},
            {"name": "bob", "role": "user", "token": "b"},
            {"name": "root", "role": "admin", "token": "r"},
        ],
        resources=[
            {"name": "get_order", "request": {"method": "GET", "path": "/orders/{id}"},
             "type": "object", "owner": "id", "objects": objects},
        ],
        policy={"get_order": {"allow": [
            {"role": "user", "scope": "own"}, {"role": "admin", "scope": "any"},
        ]}},
    )


def _sharing(matrix):
    return [p for p in matrix.diagnose() if "resolve to the same object" in str(p)]


def test_the_premise_two_sharers_are_not_probed_against_each_other():
    """What the warning describes, read off the plan rather than assumed."""
    cases = plan(_matrix({"alice": "o-1", "bob": "o-1", "root": "o-9"}))
    victims = {(c.subject, c.victim) for c in cases if c.victim}

    assert ("alice", "bob") not in victims and ("bob", "alice") not in victims
    assert ("alice", "root") in victims


def test_two_sharers_and_a_third_are_warned_about_by_name():
    problems = _sharing(_matrix({"alice": "o-1", "bob": "o-1", "root": "o-9"}))

    assert len(problems) == 1
    assert problems[0].severity is Severity.WARNING
    message = str(problems[0])
    assert "'get_order'" in message
    assert "alice, bob resolve to the same object (o-1)" in message
    assert "root" not in message


def test_distinct_objects_are_not_warned_about():
    assert _sharing(_matrix({"alice": "o-1", "bob": "o-2", "root": "o-9"})) == []


def test_everyone_on_one_object_keeps_its_own_warning_and_gets_no_second():
    matrix = _matrix({"alice": "o-1", "bob": "o-1", "root": "o-1"})

    assert _sharing(matrix) == []
    assert any("no cross-owner BOLA probe" in str(p) for p in matrix.diagnose())


def test_each_group_of_sharers_is_reported():
    matrix = _matrix({"alice": "o-1", "bob": "o-1", "root": "o-9"})
    matrix.subjects.append(type(matrix.subjects[0])(name="carol", role="admin", token="c"))
    matrix.resources[0].objects["carol"] = "o-9"

    messages = sorted(str(p) for p in _sharing(matrix))
    assert len(messages) == 2
    assert "alice, bob" in messages[0] and "root, carol" in messages[1]


def test_a_subject_with_no_object_is_not_counted_as_sharing():
    assert _sharing(_matrix({"alice": "o-1", "root": "o-9"})) == []
