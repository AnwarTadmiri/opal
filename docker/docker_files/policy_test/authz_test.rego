package authz

test_admin_can_always_add {
  allow with input as {"user": "alice", "change_request": {"status": "CLOSED"}}
}

test_cs2_blocked_if_closed {
  not allow with input as {"user": "carol", "change_request": {"status": "CLOSED"}}
}

test_cs3_only_if_drafted {
  allow with input as {"user": "dave", "change_request": {"status": "DRAFTED"}}
  not allow with input as {"user": "dave", "change_request": {"status": "APPROVED"}}
}
