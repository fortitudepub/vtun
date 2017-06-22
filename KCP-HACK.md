1. support using kcp over udp for reduce delay.
2. support generate kcp conn id through conn name, by this way we do not
   need provide a new config item.
3. support reuse keepalive interval as kcp tick.
