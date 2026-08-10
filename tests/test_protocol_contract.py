"""Run the reusable protocol surface black-box contract suite against ``masugated``."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from masugate.model import JsonValue, MasuGateMode
from masugate.resources.postgres import AsyncPostgresLedger
from tests.protocol_contract import ContractCases, run_contract_suite
from tests.test_masugated import TRANSACTION_POLICY, _action, _seed, _stack

pytestmark = pytest.mark.postgres


class _HttpxTransport:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, JsonValue] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        return await self._client.request(method, path, json=json, headers=headers)


async def test_masugated_satisfies_reusable_protocol_contract(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    await _seed(pg_ledger, 90_000)
    _coordinator, app = _stack(pg_ledger, TRANSACTION_POLICY, MasuGateMode.TRANSACTION)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        observations = await run_contract_suite(
            _HttpxTransport(client),
            ContractCases(
                bearer_token="alice-token",
                committed_action=_action("contract-commit", amount=1_000),
                denied_action=_action("contract-deny", amount=20_000),
            ),
        )
    assert set(observations) == {
        "committed",
        "retry",
        "denied",
        "invalid",
        "unauthenticated",
    }
