SELECT
    EXISTS (
        SELECT 1
        FROM auth_outbox AS unsettled
        WHERE unsettled.kind = 'relationship'
          AND unsettled.resource_type = $1
          AND unsettled.resource_id = $2
          AND unsettled.status <> 'delivered'
    ) AS has_unsettled,
    (
        SELECT delivered.delivery_id
        FROM auth_outbox AS delivered
        WHERE delivered.kind = 'relationship'
          AND delivered.resource_type = $1
          AND delivered.resource_id = $2
          AND delivered.status = 'delivered'
          AND delivered.delivery_id IS NOT NULL
        ORDER BY delivered.resource_revision DESC,
                 delivered.delivered_at_ms DESC,
                 delivered.outbox_id DESC
        LIMIT 1
    ) AS consistency_token,
    (
        SELECT max(scoped.resource_revision)
        FROM auth_outbox AS scoped
        WHERE scoped.kind = 'relationship'
          AND scoped.resource_type = $1
          AND scoped.resource_id = $2
    ) AS resource_revision
