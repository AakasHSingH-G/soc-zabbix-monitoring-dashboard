<?php
// Legacy compatibility configuration. Values are non-functional decoy placeholders.
return [
    'app_name' => 'Northstar Relay',
    'environment' => 'production',
    'database' => [
        'host' => 'db-relay-01.internal',
        'port' => 5432,
        'name' => 'relay_events',
        'username' => 'relay_reader',
        'password' => 'not-a-real-password',
    ],
    'api' => [
        'base_url' => 'http://relay-api.internal/v1',
        'key' => 'decoy-key-0000000000000000',
    ],
];
