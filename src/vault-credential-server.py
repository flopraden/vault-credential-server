#!/usr/bin/env python3

import aiohttp
import asyncio
import ipaddress
import logging
from os import environ
from pathlib import Path
import socket
import sys

from systemd import journal
import systemd.daemon

log = logging.getLogger("vault-credential-server")
log.propagate = False
log.addHandler(journal.JournalHandler(SYSLOG_IDENTIFIER="vault-credential-server"))
log.setLevel(logging.INFO)


class VaultCredentialServer:
    def __init__(self) -> None:
        if "VAULT_ADDR" not in environ:
            raise Exception("No VAULT_ADDR set")

        if "CREDENTIALS_DIRECTORY" not in environ:
            raise Exception("No CREDENTIALS_DIRECTORY set")

        socket_fds = systemd.daemon.listen_fds()
        if len(socket_fds) == 0:
            log.info("No sockets passed, exiting")
            sys.exit(0)
        elif len(socket_fds) > 1:
            log.warn("More than 1 socket passed, not supported")
            sys.exit(1)
        self.socket = socket.socket(fileno=socket_fds[0])

    def client_connected_cb(self, reader, writer):
        asyncio.create_task(self.handle_connection(reader, writer))

    async def handle_connection(self, reader, writer):
        _, _, service, credential = (
            writer.get_extra_info("peername").decode("utf-8").split("/")
        )
        log.info("Got connection from %s, credential %s", service, credential)
        try:
            service, _ = service.split(".")
            if service.startswith("vault-agent@"):
                _, service = service.split("@")
            if credential == "role-id":
                value = await self._get_vault_approle_id(service)
            elif credential == "secret-id":
                value = await self._get_vault_approle_credential(service)
            else:
                value = await self._get_vault_server_secret(service, credential)

            writer.write(str(value).encode("utf-8"))
            await writer.drain()
        except Exception as e:
            log.exception(e)
        finally:
            writer.close()
            await writer.wait_closed()

    async def run(self):
        ttl = await self._vault_login()

        server = await asyncio.start_unix_server(
            self.client_connected_cb, sock=self.socket
        )
        async with server:
            await server.start_serving()
            # wait until 70% of vault token ttl has gone, then exit
            await asyncio.sleep(int(ttl * 0.7))
            server.close()
            await server.wait_closed()

    async def _vault_login(self):
        role_id, secret_id = self._get_vault_credentials()
        self.vault_session = aiohttp.ClientSession(base_url=environ["VAULT_ADDR"])
        async with self.vault_session.post(
            "/v1/auth/approle/login", json={"role_id": role_id, "secret_id": secret_id}
        ) as resp:
            if not resp.ok:
                raise Exception("Unable to log in to vault %s", await resp.text())
            payload = await resp.json()
            self.vault_session.headers["X-Vault-Token"] = payload["auth"][
                "client_token"
            ]
            return payload["auth"].get("lease_duration", 30)

    async def _get_vault_approle_credential(self, approle):
        addresses = []
        for family, type, proto, canonname, sockaddr in socket.getaddrinfo(
            socket.getfqdn(), 8200
        ):
            if not (ip := ipaddress.ip_address(sockaddr[0])).is_private:
                addresses.append(ip)
        if len(addresses) == 0:
            ip_session = aiohttp.ClientSession()
            async with ip_session.get("https://api.ipify.org") as resp:
                public_ip = await resp.text()
                addresses.append(ipaddress.ip_address(public_ip.strip()))

        cidr_list = []
        for addr in addresses:
            if isinstance(addr, ipaddress.IPv4Address):
                net = ipaddress.IPv4Network(addr)
                cidr_list.append(net.with_prefixlen)
            else:
                net = ipaddress.IPv6Network(addr).supernet(64)
                cidr_list.append(net.with_prefixlen)

        path = f"/v1/auth/approle/role/{approle}/secret-id"
        headers = {"X-Vault-Wrap-TTL": "5m"}

        async with self.vault_session.post(
            path, json={"cidr_list": cidr_list}, headers=headers
        ) as resp:
            if not resp.ok:
                if resp.status == 403:
                    raise Exception("Permission denied getting approle token")
                else:
                    raise Exception("Unable to get vault data: %s", await resp.text())
            data = await resp.json()
            return data["wrap_info"]["token"]

    async def _get_vault_approle_id(self, approle):
        path = f"/v1/auth/approle/role/{approle}/role-id"

        async with self.vault_session.get(path) as resp:
            if not resp.ok:
                if resp.status == 403:
                    raise Exception("Permission denied getting approle id")
                else:
                    raise Exception("Unable to get vault data: %s", await resp.text())
            data = await resp.json()
            return data["data"]["role_id"]

    async def _get_vault_server_secret(self, app, credential):
        path = f"/v1/secret/servers/{socket.getfqdn()}/{app}"

        async with self.vault_session.get(path) as resp:
            if not resp.ok:
                if resp.status == 403:
                    raise Exception("Permission denied getting server secret")
                else:
                    raise Exception("Unable to get vault data: %s", await resp.text())
            data = await resp.json()
            if not credential in data["data"]:
                raise Exception(f"{credential} not found in server data for app {app}")
            return data["data"][credential]

    def _get_vault_credentials(self):
        credential_path = Path(environ["CREDENTIALS_DIRECTORY"])
        role_id_file = credential_path / Path("role-id")
        if not role_id_file.exists():
            raise Exception("No role-id file")
        secret_id_file = credential_path / Path("secret-id")
        if not secret_id_file.exists():
            raise Exception("No secret-id file")

        with role_id_file.open("r") as f:
            role_id = f.read()
        with secret_id_file.open("r") as f:
            secret_id = f.read()

        return (role_id, secret_id)


if __name__ == "__main__":
    vault_credential_server = VaultCredentialServer()
    try:
        asyncio.run(vault_credential_server.run())
    except Exception as e:
        log.exception(e)
        sys.exit(2)
