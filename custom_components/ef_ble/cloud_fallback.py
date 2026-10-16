"""Cloud WSS fallback bridge for ef_ble using an active ecoflow_energy coordinator."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from functools import partial
import logging
import time
from typing import TYPE_CHECKING, Any

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr

from .config_flow import CONF_COLLECT_PACKETS, ConfLogOptions
from .const import (
    CONF_COLLECT_PACKETS_AMOUNT,
    CONF_DEVICE_OPTIONS,
    CONF_DIAGNOSTICS_ON_EXCEPTION,
    CONF_DIAGNOSTICS_OPTIONS,
    DOMAIN,
)
from .eflib import DeviceBase, NewDevice, is_unsupported
from .eflib.connection import ConnectionState
from .eflib.exceptions import NotConnectedError
from .eflib.packet import Packet
from .eflib.pb import bk_series_pb2

if TYPE_CHECKING:
    pass

_LOGGER = logging.getLogger(__name__)


def _encode_varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def _encode_field_varint(field_num: int, value: int) -> bytes:
    return _encode_varint((field_num << 3) | 0) + _encode_varint(value)


def _encode_field_bytes(field_num: int, data: bytes) -> bytes:
    return _encode_varint((field_num << 3) | 2) + _encode_varint(len(data)) + data


def build_wss_proto_envelope(packet: Packet, device_sn: str, seq: int = 0) -> bytes:
    """Wrap an ef_ble Packet into an EcoFlow App WSS HeaderMessage protobuf payload."""
    if seq == 0:
        seq = int(time.time() * 1000) & 0x7FFFFFFF
    pdata = packet.payload
    header = bytearray()
    header.extend(_encode_field_bytes(1, pdata))  # pdata
    header.extend(_encode_field_varint(2, packet.src or 32))  # src = 32 (App)
    header.extend(_encode_field_varint(3, packet.dst or 2))  # dest = 2
    header.extend(_encode_field_varint(4, packet.dsrc or 1))  # d_src = 1
    header.extend(_encode_field_varint(5, packet.ddst or 1))  # d_dest = 1
    header.extend(_encode_field_varint(7, 3))  # check_type = 3
    header.extend(_encode_field_varint(8, packet.cmd_set))  # cmd_func (e.g. 254)
    header.extend(_encode_field_varint(9, packet.cmd_id))  # cmd_id (e.g. 17)
    header.extend(_encode_field_varint(10, len(pdata)))  # data_len
    header.extend(_encode_field_varint(11, 1))  # need_ack = 1
    header.extend(_encode_field_varint(14, seq))  # seq
    header.extend(_encode_field_varint(16, 3))  # version = 3
    header.extend(_encode_field_varint(17, 1))  # payload_ver = 1
    header.extend(_encode_field_bytes(23, b"ios"))  # from = "ios"
    header.extend(_encode_field_bytes(25, device_sn.encode("ascii")))  # deviceSn
    return _encode_field_bytes(1, bytes(header))


def find_ecoflow_energy_coordinator(hass: HomeAssistant, serial_number: str) -> Any | None:
    """Find a running ecoflow_energy coordinator for the given device serial number."""
    ee_data = hass.data.get("ecoflow_energy")
    if not isinstance(ee_data, dict):
        return None
    for entry_coordinators in ee_data.values():
        if isinstance(entry_coordinators, dict) and serial_number in entry_coordinators:
            return entry_coordinators[serial_number]
    return None


def create_device_from_registry(hass: HomeAssistant, address: str) -> DeviceBase | None:
    """Instantiate an eflib DeviceBase from HA device registry when BLE advertisement is absent."""
    device_reg = dr.async_get(hass)
    if hasattr(device_reg, "async_get_device_by_identifier"):
        device_entry = device_reg.async_get_device_by_identifier((DOMAIN, address))
    else:
        device_entry = device_reg.async_get_device(identifiers={(DOMAIN, address)})
    if device_entry is None or not device_entry.serial_number:
        return None

    sn = device_entry.serial_number
    local_name = device_entry.name or f"EF-{sn[-4:]}"
    ble_dev = BLEDevice(address=address, name=local_name, details=None)
    adv_data = AdvertisementData(
        local_name=local_name,
        manufacturer_data={
            DeviceBase.MANUFACTURER_KEY: b"\x13" + sn.encode("ascii") + b"\x00" * 6
        },
        service_data={},
        service_uuids=[],
        tx_power=-127,
        rssi=-60,
        platform_data=(),
    )
    return NewDevice(ble_dev, adv_data)


class CloudFallbackBridge:
    """Bridges an eflib DeviceBase to an ecoflow_energy coordinator over App WSS."""

    def __init__(
        self,
        hass: HomeAssistant,
        device: DeviceBase,
        coordinator: Any,
        serial_number: str,
    ) -> None:
        self.hass = hass
        self.device = device
        self.coordinator = coordinator
        self.serial_number = serial_number
        self._attached = False
        self._initial_data_event = asyncio.Event()
        self._poll_handle: asyncio.TimerHandle | None = None
        self._refresh_handle: asyncio.TimerHandle | None = None

    @property
    def is_available(self) -> bool:
        if not self._attached:
            return False
        mqtt_client = getattr(self.coordinator, "_mqtt_client", None)
        if mqtt_client is not None and mqtt_client.is_connected():
            return True
        return bool(getattr(self.coordinator, "available", False))

    def attach(self) -> None:
        """Hook into the ecoflow_energy coordinator's MQTT message stream."""
        if self._attached:
            return
        self._attached = True

        callbacks: set[Callable[[str, bytes], None]] | None = getattr(
            self.coordinator, "_ef_ble_raw_callbacks", None
        )
        if callbacks is None:
            callbacks = set()
            setattr(self.coordinator, "_ef_ble_raw_callbacks", callbacks)
            orig_on_mqtt = self.coordinator._on_mqtt_message

            def _wrapped_on_mqtt_message(topic: str, payload: bytes) -> None:
                orig_on_mqtt(topic, payload)
                for cb in list(callbacks):
                    try:
                        cb(topic, payload)
                    except Exception:
                        _LOGGER.debug("Error in ef_ble cloud fallback callback", exc_info=True)

            self.coordinator._on_mqtt_message = _wrapped_on_mqtt_message
            mqtt_client = getattr(self.coordinator, "_mqtt_client", None)
            if mqtt_client is not None:
                mqtt_client.message_handler = _wrapped_on_mqtt_message

        callbacks.add(self._on_raw_mqtt)
        self._schedule_periodic_get_all()
        self.device._schedule_missing_field_defaults(ConnectionState.AUTHENTICATED)
        _LOGGER.info(
            "Attached ef_ble Cloud WSS fallback bridge for %s (%s)",
            self.device.name,
            self.serial_number,
        )

    def detach(self) -> None:
        """Unhook from the ecoflow_energy coordinator."""
        if not self._attached:
            return
        self._attached = False
        if self._poll_handle is not None:
            self._poll_handle.cancel()
            self._poll_handle = None
        if self._refresh_handle is not None:
            self._refresh_handle.cancel()
            self._refresh_handle = None
        callbacks: set[Callable[[str, bytes], None]] | None = getattr(
            self.coordinator, "_ef_ble_raw_callbacks", None
        )
        if callbacks is not None:
            callbacks.discard(self._on_raw_mqtt)
        _LOGGER.info(
            "Detached ef_ble Cloud WSS fallback bridge for %s (%s)",
            self.device.name,
            self.serial_number,
        )

    def _schedule_periodic_get_all(self, delay: float = 60.0) -> None:
        if not self._attached or self.hass.loop.is_closed():
            return
        if self._poll_handle is not None:
            self._poll_handle.cancel()
        self._poll_handle = self.hass.loop.call_later(delay, self._on_periodic_get_all)

    def _on_periodic_get_all(self) -> None:
        self._poll_handle = None
        if not self._attached:
            return
        self.hass.async_create_task(self.async_trigger_get_all())
        self._schedule_periodic_get_all(60.0)

    async def async_trigger_get_all(self) -> bool:
        mqtt_client = getattr(self.coordinator, "_mqtt_client", None)
        if mqtt_client is None or not mqtt_client.is_connected():
            return False
        try:
            return await self.hass.async_add_executor_job(mqtt_client.send_get_all)
        except Exception:
            _LOGGER.debug("Failed to send get_all for %s", self.serial_number, exc_info=True)
            return False

    async def async_request_initial_state(self, timeout: float = 3.0) -> None:
        """Trigger a full get_all dump and wait briefly for initial protobuf state."""
        await self.async_trigger_get_all()
        try:
            await asyncio.wait_for(self._initial_data_event.wait(), timeout=timeout)
        except TimeoutError:
            _LOGGER.debug(
                "Initial get_all reply for %s did not arrive within %.1fs; entities will update on next push",
                self.serial_number,
                timeout,
            )

    def _on_raw_mqtt(self, topic: str, payload: bytes) -> None:
        """Handle raw MQTT message on Paho thread."""
        if not self._attached:
            return
        if topic.endswith("/set_reply") or topic.endswith("/thing/property/set"):
            return

        packets = self._extract_packets(payload)
        if not packets:
            return

        if not self.hass.loop.is_closed():
            try:
                self.hass.loop.call_soon_threadsafe(self._dispatch_packets, packets)
            except RuntimeError:
                pass

    def _extract_packets(self, payload: bytes) -> list[Packet]:
        try:
            from custom_components.ecoflow_energy.ecoflow.parsers.stream_proto import (
                _pdata_candidates,
            )
            from custom_components.ecoflow_energy.ecoflow.proto.decoder import (
                decode_header_message,
            )
        except ImportError:
            return []

        try:
            headers, _ = decode_header_message(payload)
        except Exception:
            return []
        if not headers:
            return []

        packets: list[Packet] = []
        for header in headers:
            cmd_func = int(header.get("cmd_func", -1))
            cmd_id = int(header.get("cmd_id", -1))
            if cmd_func < 0 or cmd_id < 0:
                continue
            candidates = _pdata_candidates(header)
            if not candidates:
                continue

            chosen_pdata = candidates[0]
            if cmd_func == 0xFE and cmd_id == 0x15 and len(candidates) > 1:
                for cand in candidates:
                    try:
                        msg = bk_series_pb2.DisplayPropertyUpload()
                        msg.ParseFromString(cand)
                        chosen_pdata = cand
                        break
                    except Exception:
                        continue

            packets.append(
                Packet(
                    src=0x02,
                    dst=0x20,
                    cmd_set=cmd_func,
                    cmd_id=cmd_id,
                    payload=chosen_pdata,
                    dsrc=0x01,
                    ddst=0x01,
                    version=0x13,
                )
            )
        return packets

    def _dispatch_packets(self, packets: list[Packet]) -> None:
        if not self._attached:
            return
        self.hass.async_create_task(self._async_parse_packets(packets))

    async def _async_parse_packets(self, packets: list[Packet]) -> None:
        for pkt in packets:
            try:
                if await self.device.data_parse(pkt):
                    self._initial_data_event.set()
            except Exception:
                _LOGGER.debug(
                    "Error parsing cloud fallback packet for %s",
                    self.device.name,
                    exc_info=True,
                )

    async def async_send_packet(
        self,
        packet: Packet,
        *,
        raise_on_failure: bool = False,
    ) -> None:
        """Send an ef_ble control packet over the ecoflow_energy WSS channel."""
        if not self.is_available:
            if raise_on_failure:
                raise NotConnectedError(
                    f"{self.device.name}: cloud fallback coordinator is not connected"
                )
            return

        wss_payload = build_wss_proto_envelope(packet, self.serial_number)
        label = f"ef_ble_fallback_{packet.cmd_set}_{packet.cmd_id}"
        ok = await self.coordinator.async_send_proto_set_command(wss_payload, label)
        if not ok and raise_on_failure:
            raise NotConnectedError(
                f"{self.device.name}: failed to deliver packet via cloud fallback"
            )

        # Schedule get_all refreshes at 1.5s and 4.5s after a write so timer tasks & settings update immediately
        if self._refresh_handle is not None:
            self._refresh_handle.cancel()

        async def _delayed_refreshes() -> None:
            await self.async_trigger_get_all()
            await asyncio.sleep(3.0)
            if self._attached:
                await self.async_trigger_get_all()

        self._refresh_handle = self.hass.loop.call_later(
            1.5,
            lambda: self.hass.async_create_task(_delayed_refreshes()),
        )


async def async_try_setup_cloud_fallback(
    hass: HomeAssistant,
    entry: ConfigEntry,
    address: str,
    update_period: int,
    merged_options: dict[str, Any],
) -> DeviceBase | None:
    """Attempt to set up or attach a CloudFallbackBridge for an unreachable BLE device."""
    device: DeviceBase | None = getattr(entry, "runtime_data", None)
    if device is None:
        device = create_device_from_registry(hass, address)
        if device is None:
            return None
        entry.runtime_data = device

    sn = device.serial_number
    coordinator = find_ecoflow_energy_coordinator(hass, sn)
    if coordinator is None:
        _LOGGER.debug(
            "No ecoflow_energy coordinator found for %s (%s); cloud fallback unavailable",
            device.name,
            sn,
        )
        return None

    mqtt_client = getattr(coordinator, "_mqtt_client", None)
    if mqtt_client is None or not mqtt_client.is_connected():
        _LOGGER.debug(
            "ecoflow_energy coordinator for %s (%s) is not connected to MQTT yet",
            device.name,
            sn,
        )
        return None

    diag_options = merged_options.get(CONF_DIAGNOSTICS_OPTIONS, {})
    packet_collection = diag_options.get(
        CONF_COLLECT_PACKETS, is_unsupported(device)
    )
    diagnostics_buffer_size = diag_options.get(CONF_COLLECT_PACKETS_AMOUNT, 100)
    diagnostics_on_exception = diag_options.get(CONF_DIAGNOSTICS_ON_EXCEPTION, False)

    (
        device.with_update_period(period=update_period)
        .with_logging_options(ConfLogOptions.from_config(merged_options))
        .with_advanced_options(merged_options.get(CONF_DEVICE_OPTIONS, {}))
        .with_enabled_packet_diagnostics(
            enabled=packet_collection,
            buffer_size=diagnostics_buffer_size,
        )
        .with_diagnostics_on_exception(diagnostics_on_exception)
    )

    old_bridge: CloudFallbackBridge | None = getattr(device, "_cloud_bridge", None)
    if old_bridge is not None:
        old_bridge.detach()

    bridge = CloudFallbackBridge(hass, device, coordinator, sn)
    setattr(device, "_cloud_bridge", bridge)
    bridge.attach()
    await bridge.async_request_initial_state(timeout=3.0)
    return device
