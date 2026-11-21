"""Exercise the official Python SDK's OAuth provider and Streamable HTTP session."""

import asyncio
import logging
import os
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.auth import OAuthClientMetadata
from pydantic import AnyUrl


class Storage:
    tokens = None
    client = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.client

    async def set_client_info(self, client_info):
        self.client = client_info


async def main():
    origin = os.environ["OAUTH_TEST_ORIGIN"]
    result = asyncio.get_running_loop().create_future()

    async def callback(reader, writer):
        request = (await reader.readline()).decode().split()
        query = parse_qs(urlsplit(request[1]).query)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        result.set_result((query["code"][0], query["state"][0]))

    listener = await asyncio.start_server(callback, "127.0.0.1", 0)
    redirect = f"http://127.0.0.1:{listener.sockets[0].getsockname()[1]}/callback"

    async def browser(url):
        proc = await asyncio.create_subprocess_exec(os.environ["BROWSER"], url)
        assert await proc.wait() == 0, "browser substitute"

    async def callback_result():
        return await asyncio.wait_for(result, timeout=15)

    url = origin + "/mcp/legacy"
    storage = Storage()
    auth = OAuthClientProvider(
        url,
        OAuthClientMetadata(
            client_name="Humaux CI Python SDK",
            redirect_uris=[AnyUrl(redirect)],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
            scope="memory:write",
        ),
        storage,
        redirect_handler=browser,
        callback_handler=callback_result,
    )

    async def use_tools(session):
        catalog = await session.list_tools()
        assert any(tool.name == "remember" for tool in catalog.tools)
        reply = await session.call_tool("remember", {
            "action": "put",
            "content": "Synthetic OAuth SDK acceptance",
            "workspace_id": os.environ["OAUTH_TEST_WORKSPACE"],
            "idempotency_key": str(uuid4()),
        })
        assert not reply.isError and isinstance(reply.structuredContent.get("evidence_id"), str)

    async with listener, streamablehttp_client(url, auth=auth) as (receive, send, _):
        async with ClientSession(receive, send) as session:
            initialized = await session.initialize()
            assert initialized.protocolVersion == "2025-06-18"
            await use_tools(session)
            assert storage.tokens.expires_in == 300
            await asyncio.sleep(301)
            await use_tools(session)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(main())
    except Exception:
        raise SystemExit("Python SDK failed the OAuth or tool journey") from None
