# default-user-credential-updater

This is a program that watches a directory containing RabbitMQ user credential files (with prefix `user_`).
If any credential file changes, it updates the corresponding user's password in RabbitMQ.

It is meant to be deployed as a sidecar container, when several non-default users credentials need to be rotated.

The use case is as-follows:
1. User passwords change in Vault server.
1. Vault agent sidecar places new credentials into files with pattern `user_<name>_<field>` in the watched directory.
1. This sidecar (default-user-credential-updater) updates the passwords RabbitMQ server side by doing HTTP PUT requests against the RabbitMQ Management API. This allows for password rotation without the need to restart RabbitMQ server.
1. For admin user updates, this sidecar also copies new credentials to `/var/lib/rabbitmq/.rabbitmqadmin.conf` to be used by `rabbitmqadmin` CLI.
