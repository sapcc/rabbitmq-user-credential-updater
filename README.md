# default-user-credential-updater

This is a program that watches a RabbitMQ config file containing `default_user` and `default_pass` for changes.
If the file changes, it updates the password in RabbitMQ.

It is meant to be deployed as a sidecar container by https://github.com/rabbitmq/cluster-operator when HashiCorp Vault is enabled.

The use case is as-follows:
1. Default user password changes in Vault server.
1. Vault agent sidecar places new password into `/etc/rabbitmq/conf.d/11-default_user.conf`.
1. This sidecar (default-user-credential-updater) updates the password RabbitMQ server side by doing an HTTP PUT against the RabbitMQ Management API. This allows for default user password rotation without the need to restart RabbitMQ server.
1. This sidecar copies new password to `/var/lib/rabbitmq/.rabbitmqadmin.conf` to be used by `rabbitmqadmin` CLI.

See [vault-default-user](https://github.com/rabbitmq/cluster-operator/tree/main/docs/examples/vault-default-user) for an end-to-end example.
