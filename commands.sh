# To see active exit node
tailscale status --peers --json   | jq '.ExitNodeStatus.ID as $node_id | .Peer[] | select(.ID==$node_id) | .HostName'
