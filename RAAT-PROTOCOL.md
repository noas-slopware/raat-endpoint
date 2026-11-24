# RAAT endpoint protocol, as implemented by RoonBridge 2.71 (build 1683), linux x64

Interoperability notes derived from static analysis only. No Roon code was executed and
no Roon service or LAN host was contacted. Every claim carries a reference:

- `src/<Assembly>/<path>.cs:<line>`: ILSpy 11.2 C# decompile of the managed assemblies.
- `native/libraatmanager.c:<line> (<func>)`: Ghidra 12.1.2 headless decompile of
  `extract/RoonBridge/Bridge/libraatmanager.so`. Line numbers are those of the function
  header unless a body line is given. Ghidra loaded the library at base `0x100000`, so
  Ghidra address `X` is ELF vaddr `X - 0x100000`. `FUN_xxxxxxxx` names are Ghidra
  auto-names for stripped internal functions. Exported names (`RAAT__*`, `RNET__*`, `RC__*`)
  are the vendor's own.
- `native/lua_reg_tables.txt`: every `luaL_Reg` table recovered from the library's
  `R_X86_64_RELATIVE` relocations, made by a scratch script.
- `native/libraatmanager.strings.txt`: `strings -t x` dump (hex file offsets).

Confidence tags: **[verified]** means read directly from code. **[inferred]** means a
reasoned reading of code that is not explicit. **[not derivable]** means the logic is
not in this build (see section 3).

---

## 0. Provenance

| Item | Value |
|---|---|
| Installer URL | `http://download.roonlabs.com/builds/roonbridge-installer-linuxx64.sh`, which redirects with a 301 to `http://download.roonlabs.net/builds/...` |
| Installer | 17,434 bytes, sha256 `a3dc24774365bb0d7240d0fd2d8fe3063c4a82d4f075f9bf99681d4672afbbf8`, Last-Modified 2026-03-17 |
| Payload URL | `https://download.roonlabs.net/builds/RoonBridge_linuxx64.tar.bz2` (`PACKAGE_URL`, `dl/roonbridge-installer-linuxx64.sh:9`). The installer only downloads it and untars it. There is no embedded archive. |
| Payload | 13,768,080 bytes, sha256 `d8220de59b81724069adf9bb2a57f0af1758ffdc15fb9b59e1f8d6886b4ef3b0`, Last-Modified 2026-08-31 |
| `RoonBridge/VERSION` | `207101683` / `2.71 (build 1683) production` / `production` (identical to `Bridge/VERSION`) |
| Runtime | self-contained .NET, `tfm net10.0`, Microsoft.NETCore.App 10.0.10 (`Bridge/RAATServer.runtimeconfig.json`) |
| Installer service env | `ROON_DATAROOT=/var/roon`, `ROON_ID_DIR=/var/roon` (`dl/roonbridge-installer-linuxx64.sh:270-271`) |

The directory `roonbridge-copy/` already existed before this work, holding only `RoonMono`, `start.sh` and `check.sh`. It was not touched.

## 1. Inventory

### 1.1 Managed (decompiled into `src/`)

The Roon-specific assemblies are Base, Broker.Messages.Core, Messaging, Metadata.Messages,
RAATServer, RAATServerApp, RoonApp, RoonApp.PlatformTools, RoonBase, RoonBridge,
RoonBridgeHelper, Roon.Messages, Roon.ServiceProxy.Base, Roon.ServiceProxy.DeviceMapService,
Roon.ServiceProxy.DiscoveryService and ServiceManager. In total they decompiled to 772 `.cs`
files. The rest are BCL or third-party assemblies: System.*, Microsoft.*, MessagePack,
DnsClient, SharpZipLib, LevelDb.Database and the JetBrains profiler shims.
`RoonBridge`, `RoonBridgeHelper`, `RAATServer` and `RoonBridge.exe` are ELF apphosts. All
four share one BuildID, and `Bridge/RoonBridge` is a shell launcher.

**Obfuscation and encryption:** none on the managed side. The assemblies have no
obfuscator markers, and ILSpy produced readable names, string literals and control flow,
with empty `.log` files. The managed RAAT code is tiny:
`src/RAATServer/Roon/RAATServerMain.cs` is 11 lines and `src/RAATServerApp/` is 503 lines.
Everything protocol-relevant is native.

### 1.2 Native

| File | What it is |
|---|---|
| `libraatmanager.so` (2.49 MB, stripped, 5,641 dynamic exports) | **The whole RAAT implementation.** It statically bundles libuv, Lua 5.3, luv (Lua libuv bindings), jansson (JSON), reference libFLAC 1.5.0, hidapi (MQA USB device support; `libusb_*` symbols are undefined and there is no libusb NEEDED entry, so libusb is presumably loaded at runtime or optional, which was not verified), Monocypher (Ed25519/X25519/ChaCha20/Poly1305/BLAKE2b/Argon2i) and a libstdc++ runtime. Its only NEEDED libraries are libasound.so.2 and libc/libm/libdl/librt/libpthread. The RAAT API is exported as `RAAT__*` and the JSON-RPC layer as `RNET__*`. |
| `libroonbase.so` (5.8 KB) | Exports only `linux_watch_mounts`, `native_alloc_and_leak` and `native_crash`. Not RAAT. |
| `libleveldb.so` | LevelDB. Not used on the RAAT path. |
| `check_alsa`, `check_bincompat`, `processreaper`, `relaunch`, `createdump` | Small helpers for preflight, child reaping and relaunch, plus the .NET dump tool. `check_alsa` only imports `snd_card_next`. |
| `libcoreclr.so`, `libclrjit.so`, `libhostfxr.so`, `libSystem.*.so` and others | The .NET runtime. |
| `raat.dat` (73,200 bytes) | **Opaque.** Its byte entropy is 7.9976 bits/byte and it has no magic. No file in the package references the name, in ASCII or UTF-16, and `libraatmanager.so` has no `fopen` or `luaL_loadfile` path that could reach it (the callers are listed in `native/libraatmanager.c`: config files, `/proc/asound`, `/roon/sys/image_info`). The capture shows what it is: the Core names its scripts `raat.dat:base.lua`, `raat.dat:dkjson.lua`, `raat.dat:protocol.lua` and `raat.dat:roon_tcp.lua` (`capture/decoded/frames.jsonl:39-42`). So `raat.dat` is the Core-side script bundle, and the bridge never reads its own copy. It was not decoded, and there is no need to: the scripts arrive in plaintext. |

The only Monocypher routine called from RAAT code is `crypto_ed25519_check`, from
`RAAT__device_check_code_signature` (`native/libraatmanager.c:16349`). No RAAT code calls
`crypto_lock`/`crypto_unlock`, ChaCha20, X25519 or Argon2. The poly1305/blake2b callers
(`FUN_002838f0`, `FUN_00283d20` and others near line 141789) are Monocypher internals.
**The control and audio paths implemented in this binary use no encryption.** **[verified]**

## 2. Process architecture

```
start.sh ──> Bridge/RoonBridge (sh) ──> RoonBridge.exe (App)
                                         ├── RAATServer        (child 0: the RAAT endpoint)
                                         └── RoonBridgeHelper  (child 1: updates, device map, helper SOOD)
```

- **RoonBridge** is a supervisor. It finds the two binaries
  (`src/RoonBridge/Sooloos/App.cs:133-137`) and runs a restart loop for each one, with a
  2 s back-off (`App.cs:94-124`, `154-225`). If an update is staged it exits with code
  122, and `start.sh` then re-execs (`App.cs:247-263`, `extract/RoonBridge/start.sh`).
- **RAATServer** is a thin C# host (`src/RAATServerApp/Sooloos/RAATServerApp.cs`):
  - It refuses to run without ALSA (`:23-45`, `:228`).
  - It loads or creates a persistent `unique_id` GUID (`:233-259`).
  - It reads the machine id, name, OS, vendor and model (`:270-275`).
  - It calls `RAAT__manager_new(...)` with service id `d7634b85-8190-470f-aa51-6cb5538dc1b9`
    (`:286`, `src/RoonBase/Sooloos/RAATServer.cs:10-12`), then `RAAT__manager_set_bits` and
    `RAAT__manager_run`, which blocks in libuv (`:359-366`).
  - It registers `com.roonlabs.raatserver.tcp` with Roon's ServiceManager, using the
    `tcp_port` reported by the manager (`:295-335`).
- **Ref-count liveness:** RAATServer listens on loopback TCP `RefCountPort`. This is 9004
  for production and 9005 for `-dev`, otherwise random or set by `-refcountport`
  (`RAATServer.cs:16-43`). It exits 10 s after start if nobody is connected, and when the
  last connection closes (`RAATServerApp.cs:99-192`). RoonBridge holds one such connection
  (`RAATServer.cs:45-103`). A native endpoint does not need any of this.
- **RoonBridgeHelper** is not part of audio. It answers SOOD queries for service id
  `5a955bb8-9673-4f8d-9437-4c6b7b18fba8` and runs a JSON server in ports 9250-9300 for the
  `updates_*` and `set_update_mode` requests
  (`src/RoonBridgeHelper/Sooloos/RoonBridgeHelperServer.cs:25`, `:171-216`, `:250-372`,
  `src/RoonBase/Sooloos/RoonPorts.cs:27-29`). A native endpoint can omit it. The Core then
  cannot offer software updates for the device, which is fine.
- **IPC** between the three processes is only process supervision plus the loopback
  ref-count socket. RAATServer talks to the Core directly.

**Inside `libraatmanager.so`** there are two layers. The device and server layers are
`RAAT__device_*`/`RAAT__server_*`.

1. **Manager.** `RAAT__manager_*` (`native/libraatmanager.c:2531`) owns:
   - SOOD discovery on UDP 9003;
   - a JSON-RPC server (`RNET__json_server`) bound in TCP 9200-9250
     (`RAAT__manager_run`, line 2420: `set_port_range(0x23f0, 0x2422)`);
   - the ALSA device watcher (`FUN_001c7ce0`, line 13525);
   - one *RAAT device* per enabled output.
2. **Device.** Each enabled output is wrapped by `RAAT__wrap_new` (line 2784). It gets its
   own `RAAT__device`, its own LL TCP server on an ephemeral port, and output and volume
   plugins. Per-device discovery is disabled with `RAAT__device_disable_discovery`
   (line 2832), so the Core reaches devices only through the manager.

## 3. The central fact: the session logic is Core-supplied Lua

The device does not contain the RAAT streaming protocol. When a Core connects to a device's
TCP server, the device creates a **fresh Lua 5.3 VM** with luv, standard libs and a `raat.*`
C API (`RAAT__session_new`, line 22997). The Core then sends **signed Lua source** with the
`load_script` request (`FUN_001d3350`, line 21896). The script:

- registers `raat.session.message_handlers` and `shutdown_handlers`;
- runs a `uv.run()` loop on its own thread (`FUN_001d58b0`, line 23326, loads the 8-byte
  chunk `uv.run()` at `DAT_002f35a2`);
- drives the output plugin through `raat.output.*`.

The protocol above the C layer is decided by that script. That covers audio payload
framing, clock-sync message exchange, any UDP sockets (via luv), whether FLAC is used on the
wire (the `codec` module), and start/stop/seek semantics. **None of that script is in this
build** **[verified]**:

- There is no Lua source or `\x1bLua` bytecode in `.rodata`.
- The only `luaL_loadbufferx` calls on RAAT paths load three things:
  - the Core-supplied script (lines 22966, 22977);
  - `uv = require('luv')` (line 23049);
  - a one-line `on_script_error` handler (line 23054).

**Consequence for a native endpoint:** it must embed a Lua 5.3 interpreter plus luv
(libuv). It must also re-implement the `raat.*` binding surface in section 7 with exactly
matching names, argument orders and callback semantics, because Roon's script will call it.

**Update (capture of 2026-11-24).** The four scripts a real Core sent to this RoonBridge
were captured as plaintext `load_script` requests. Section 13 documents the session, audio
and clock protocol they implement, and the exact `raat.*`, `buffer`, `stream`, `codec` and
luv calls they make. Those scripts are files under `capture/decoded/` and are cited as
`script-N.lua:line`.

## 4. Discovery (SOOD)

The managed implementation is `src/RoonBase/Sooloos.SOOD/{Connection,Utils}.cs`. The native
one is `RAAT__discovery_*` (`native/libraatmanager.c:17025-18342`).

- **Transport [verified].**
  - UDP port **9003**. Multicast group **239.255.90.90**, TTL 2, with broadcast enabled.
  - It also sends to each subnet broadcast address and to a list of unicast IPs.
  - References: `Connection.cs:108-110`, `:546`, `:568`, `:311-330`;
    `RAAT__discovery_start` line 17025 (`uv_udp_set_membership("239.255.90.90")`);
    `RAAT__discovery_query` line 17609 (`uv_ip4_addr(...,0x232b)`).
  - If 9003 is already bound, the native code logs
    `couldn't bind to 9003 ... Counting on localhost rebroadcasts` (strings).
- **Packet [verified].** References: `Utils.cs:9-34`, `Connection.cs:744-781`,
  `native/libraatmanager.c:17950-17960`. All lengths are big-endian.

  ```
  "SOOD"            4 bytes
  0x02              version (1 byte)
  type              1 byte: 'Q' (0x51) query, 'R' (0x52) response
  repeated:
    keylen   u8 (must be != 0)
    key      UTF-8
    vallen   u16 BE (0xFFFF = null value, 0 = "")
    value    UTF-8
  ```

- **Reserved keys.**
  - `_tid` is the transaction GUID string. The response must echo the query's `_tid`
    (`Connection.cs:346-352`).
  - `_replyport` and `_replyaddr` override where the reply goes. `_replyaddr` is used for
    localhost rebroadcasts when another process owns 9003 (`Connection.cs:182-227`,
    `:796-816`).
  - Replies to multicast, broadcast or unspecified addresses are dropped (`SoodUtils.cs`).
- **Query and response.** The Core multicasts `Q` with `service_id=<guid>` (plus `_tid`).
  The RAAT manager answers only when `service_id` equals its own GUID
  (`FUN_001b3bd0`, line 884: `RC__guid_equals`). The reply is a unicast `R` to the source
  (or `_replyaddr`:`_replyport`), built by `FUN_001b3860` (line 759) with these keys:
  - `service_id` = `d7634b85-8190-470f-aa51-6cb5538dc1b9`
  - `tcp_port` (the manager's JSON-RPC port)
  - `unique_id` (persistent GUID)
  - `machine_id`, `machine_name`, `os_version`, `vendor`, `model`
  - `raat_version` = `1.1.48`, `protocol_version` = `1`, `config_version` = `1`
  - `is_dev` = `0` or `1`
  - `code_signing_keys` (comma-joined, see section 5.4)
- **Duplicates.** Query handling de-dups by `_tid` for 10 s (`Connection.cs:843-858`).
  Manager bits may set `disable_multiple_responses` (`RAAT__manager_set_bits`, line 2245).
- Unsolicited announces also exist (`[raatmanager] announcing`, `RAAT__discovery_broadcast`).
  The managed helper sends its dictionary through `Connection.SendMessage`, which builds a
  `Q` packet (`RoonBridgeHelperServer.cs:137-169`, `Connection.cs:276`). Whether the
  native manager's announce is also a `Q` was **[not verified]**.
- **Internet discovery is separate.** `ServiceManager.Registration.AddOrUpdateDevice/Service`
  (`RAATServerApp.cs:319-335`) does not use the LAN. It POSTs to
  `https://discovery.roonlabs.net/register`
  (`src/Roon.ServiceProxy.DiscoveryService/Roon.ServiceProxies.DiscoveryService/Proxy.cs:14,28-30`),
  refreshes every 120 min and expires after 480
  (`src/ServiceManager/Roon/ServiceRegistration.cs:15-23`). Requests go through an
  `AuthProvider`, and the default is `NullAuthProvider`
  (`src/Roon.ServiceProxy.Base/Roon.ServiceProxies/BaseProxy.cs:392-405`). Which provider
  RAATServer uses was not traced. LAN discovery by SOOD does not depend on this, so a
  native endpoint can skip it **[inferred]**.

## 5. Transports and framing

### 5.1 "LL" framing (manager JSON-RPC and device servers alike) [verified]

Every TCP stream on both servers uses the same framing (`FUN_001d3d80` line 22302 and
`FUN_00278bc0` line 135048 parse it; `FUN_001d2f90` line 21771, `FUN_00278420` line 134795
and `FUN_001d2ea0` line 21727 build it):

```
u32 BE  total_len   (= 8 + body_len)
u32 BE  type
body    total_len - 8 bytes; max body 0x400000 (4 MiB) else the connection is killed
```

| type | Name | Direction | Body |
|---|---|---|---|
| `0x80000001` | request | Core → endpoint | `u32 BE request_id` + JSON object (`{"request": "...", ...}`) |
| `0x80000002` | response | endpoint → Core | `u32 BE request_id` + `u8 is_final` + JSON object |
| `0x80000003` | keepalive ping | endpoint → Core. Accepted and ignored inbound. | empty |
| `0x80000004` | LL_BEGIN_KEEPALIVE | Core → endpoint | `u32 BE interval_ms`, `u32 BE timeout_ms` (body must be exactly 8 bytes, else the client is killed) |
| `0x80000005` | LL_END_KEEPALIVE | Core → endpoint | empty |
| `0x00000000`..`0x7FFFFFFF` | session message | both | opaque bytes, delivered to or from Lua (device server only) |

Notes:

- **Responses.** `is_final` is 1 for final and 0 for non-final (streaming) responses
  (`FUN_00278420` line 134795, `*(char*)(buf+4) = is_final`). The device server always sends
  1 (`FUN_001d2f90`). A request id of `0xFFFFFFFF` means no response is expected
  (`FUN_00278660` line 134867, `FUN_001d3350` line 21896, `param_3 != -1`).
- **Keepalive** (`FUN_001d3ae0` line 22216, `FUN_001d3930` line 22161, and the jsonserver
  equivalents `FUN_00278660`/`FUN_00278a20`):
  - On BEGIN the endpoint starts a repeating timer every `interval_ms`.
  - At each tick, if `now_ms - last_rx_ms <= timeout_ms`, it sends an 8-byte `0x80000003`
    frame. Otherwise it logs `client timed out` and destroys the connection.
  - `last_rx_ms` is updated on every read.
  - With no BEGIN there is no idle timeout. END stops the timer.
- **JSON errors.** Unparseable JSON gets `{"status":"InvalidJson","text":...,"line":..,"column":..,"position":..}`
  (`FUN_001d3350` start).
- **Serialization** is JSON (jansson) everywhere on the RAAT path. MessagePack ships in the
  package but nothing on the RAAT path references it. **[verified for libraatmanager; the
  managed side has no RAAT protocol code at all]**
- TCP_NODELAY is left off (`uv_tcp_nodelay(...,0)` in `FUN_001d2690` line 21394).

### 5.2 Manager JSON-RPC (TCP 9200-9250) [verified]

Dispatcher: `FUN_001b4cb0` (line 1524). Every response carries a `status` string.

| request | Fields | Behaviour |
|---|---|---|
| `enumerate_devices` | `subscription_id` | The name is tail-merged into the string `cancel_enumerate_devices` at `0x2ee949`. The endpoint registers a subscription with a "gone" handler that removes it when the TCP client disappears (`FUN_001b3700`, line 697). The first response is **non-final**: `{"status":"Success","devices":[<device>...]}`. Later changes are pushed as non-final `{"status":"DeviceAdded"\|"DeviceRemoved"\|"DeviceChanged","device":<device>}` (`LOCKED_device_notify`, line 1280). |
| `cancel_enumerate_devices` | `subscription_id` | Sends final `{"status":"Canceled"}` on the original enumerate request, and final `Success` (or `NotFound`) on this one. |
| `enable_device` | `subscription_id`, `device_id` | Increments the device's ref-count. On 0→1 it creates the RAAT device (`FUN_001b47f0`, line 1360). The reply is **non-final** `Success` or `DeviceInitFailed`. It stays open as a subscription. |
| `disable_device` | `subscription_id` | Finds the enable subscription and sends final `{"status":"Canceled"}` on it. On ref-count 1→0 it stops the device (`RAAT__wrap_stop`, then a 250 ms sleep, then `RAAT__wrap_delete`) and pushes `DeviceChanged`. The reply is final `Success` or `NotFound`. |
| `retry_device` | `device_id` | Re-tries creation of an enabled device that failed (`DeviceEnableFailed` on failure). |
| `refresh` | none | Rescans platform devices and retries enabled devices whose device is missing. |
| `get_device_config` | `device_id`, `options` | Runs on a worker thread (`FUN_001b5d00`, line 2140). Returns `config`, `device_info`, `config_info` (the settings UI model from the platform layer). May restart the device. |
| `set_device_config` | `device_id`, `config` | Worker thread (`FUN_001b5aa0`, line 2055). Persists the config (section 5.5) and restarts the device if it is running. |
| anything else | | `NotSupported`. A missing field gives `InvalidRequest`. |

**`<device>` object** (`FUN_001b3360`, line 548): `device_id`, `type`,
`error_message`, `name`, `interface_name`, `vendor`, `model`, `is_system_output`,
`auto_enable`, `no_hardware_volume`, `auto_name`, `config`, and, once enabled,
`discovery_data`. `discovery_data` is how the Core learns the device's TCP port. It is built
by `RAAT__wrap_get_discovery_data` (line 2736) and contains:

- `tcp_port`;
- every RAAT info key (section 5.3);
- `code_signing_keys`.

The values of `type` and the `device_id` format both come from the platform layer's
device struct. They are **[not verified]**: `type` is presumably `"alsa"`, and `device_id`
is derived from the ALSA card or USB identity (`FUN_001c7ce0`, around line 14940). The
shape of `config_info` (`RAAT__manager_platform_device_get_config_info`) was not traced.
See section 12.

### 5.3 Device server and identity [verified]

- **Port.** The TCP listener is per device. It binds `0.0.0.0:0`, so it is IPv4-only and
  the port is ephemeral, because the listen range is never set for wrapped devices
  (`RAAT__server_start` line 22551 builds `sin_family=2` with port 0; `FUN_001d2bb0`
  line 21608 falls back to plain bind when no range is set). The listen backlog is 10.
- **Requests on type `0x80000001`** (`FUN_001d3350`, line 21896):
  - `get_info` returns `{"status":"Success","info":{...}}`.
  - `get_log` takes `min_seq` and returns `{"status":"Success","entries":[{seq,level,time,text}]}`.
  - `clear_log`.
  - `load_script` takes `script` (Lua source string), `name`, `module` (optional), `keypair`
    and `signature`. Statuses:
    - `NotFound` when `script` is absent;
    - `InvalidCodeSignature`;
    - `UnexpectedError` when the script could not be created;
    - otherwise a deferred final reply from `FUN_001d31f0` (line 21844): `Success`,
      `ScriptError` (with `message`, for internal status 7000), or `UnexpectedError` (with
      `message` and `code`).
  - Anything else returns `NotImplemented`.
- **Module handling.** With `module` set, the chunk is stored in `package.preload[module]`
  and not run. Without it the chunk is executed (`FUN_001d4bd0`, line 22949).
- **Info dictionary.** `RAAT__info_new` (line 20261) pre-sets `raat_version="1.1.48"` and
  `protocol_version="3"` (`sprintf("%d",3)`). The wrapper sets `unique_id` from the device
  config and `vendor`, `model` and `version` to `"N/A"` (`RAAT__wrap_new`, lines 2948-2954,
  string at `0x2ef106`). The other keys it knows are `output_name`, `serial`, `config_url`,
  `vendor_model` and `app_platform` (`RAAT__info_set`, line 20088, plus strings).
  `RAAT__info_validate` (line 20318) requires `version`, `model`, `vendor`, a non-empty
  `unique_id`, `protocol_version` and `raat_version`.
- **Session messages** are frame types below `0x80000000`. Their bodies are delivered to
  every function in `raat.session.message_handlers` as `(type:int, body:string)`
  (`FUN_001d5540`, line 23242). Lua sends them with `raat.session.send_message(type, data)`
  (`FUN_001f1a70`, line 40111), and they are written verbatim as LL frames
  (`FUN_001d2ea0`, line 21727).

### 5.4 Code signing [verified]

- **Embedded key.** One public key is embedded and registered under keypair name `"Roon"`:
  Ed25519 `9bb28e4e9e34ed4ff75c6a35339497cbdd3420713c941f5468571afc03555bf7`.
  References: `RAAT__manager_new` line 2597 and `RAAT__wrap_new` line 2824; the name string
  is at file offset `0x1eea53`.
- **Advertised.** The key goes out as `code_signing_keys` in both discovery and device
  `discovery_data`.
- **Verification** (`RAAT__device_check_code_signature`, line 16349):
  - The `keypair` field must name a registered key.
  - `signature` must be 128 hex characters (64 bytes).
  - The check is `crypto_ed25519_check(sig, pubkey, script, strlen(script))`. `script` is
    the JSON-decoded string value of the `script` field (jansson
    `json_string_value`), not the escaped bytes on the wire. A string containing NUL is
    truncated at the NUL.
  - If *no* keys are registered, every script is accepted. That never happens in this
    build.
- **Direction of trust.** The endpoint verifies scripts the Core signed. The endpoint holds
  **no secret** and proves nothing to the Core. A native endpoint only needs the public key
  above to do the same check. No key, licence or DRM material has to be extracted or
  bypassed.

### 5.5 What is persisted, and where [verified, except the RAATServer app dir name (inferred)]

- **App data directory.** It is `$ROON_DATAROOT/<appdir>`, else `$HOME/.<appdir>`
  (`src/Base/Base/Utils.cs:529-542`). It is logged at startup
  (`RAATServerApp.cs:277`). With the stock service that is `/var/roon/<app>`.
- **`unique_id`.** `Settings/unique_id` holds a GUID text file (`SooloosSettings`,
  `src/RoonBase/Sooloos/SooloosSettings.cs:16`, `SooloosRegistry.cs:282-338`). The same
  `unique_id` key is used by the helper.
- **Machine id.** `MachineId.GetMachineId()` (`src/RoonBase/Sooloos/MachineId.cs:77-182`):
  - It prefers `/sys/devices/virtual/dmi/id/product_uuid`.
  - Otherwise it uses a cached or address-derived GUID.
  - The value is reported, not authenticated.
- **Per-device config.** `<appdata>/Settings/device_<id>.json` is the JSON the Core sent in
  `set_device_config`. It is deleted when the config is null (`FUN_001b4170` line 1088,
  `FUN_001b4320` line 1149, `FUN_001b43e0` line 1174).

## 6. Versioning and compatibility

**[verified for the advertised values; how the Core checks them is not derivable]**

| Where | Key | Value |
|---|---|---|
| SOOD and manager discovery | `raat_version` / `protocol_version` / `config_version` | `1.1.48` / `1` / `1` (`FUN_001b3860`) |
| Device info (`get_info`, `discovery_data`) | `raat_version` / `protocol_version` | `1.1.48` / `3` (`RAAT__info_new`) |
| Lua | `raat.platform.os` | `"linux"` (`RAAT__script_init_misc`, line 25834). The script can branch on it. |
| Lua | `raat.output.is_*_supported` and `raat.volume.is_double_volume_supported` flags | capability probes the script reads (section 7) |

The endpoint itself does no version negotiation. The Core decides which script to send,
presumably from these values. A native endpoint should advertise exactly these strings.

## 7. The `raat.*` Lua API a native endpoint must provide [verified unless noted]

The global table is `raat` (`DAT_002f357a`). It is built in `RAAT__session_new`
(line 22997) by `RAAT__script_init_*`. Functions raise Lua errors whose message is an
`RC__status` string on failure.

- **`raat.platform`**: `{os="linux", ...}`. **`raat.port_range`**: `{start_port, end_port}`
  is present only when the device has a listen range, which is never the case here
  (`RAAT__script_init_misc`).
- **`raat.log.{trace,debug,info,warning,error,critical}(msg)`**
  (`native/lua_reg_tables.txt`, table `0x550cc0`).
- **`raat.info`**: the info dictionary from section 5.3 (`RAAT__script_init_info`,
  line 37723).
- **`raat.session`** (`RAAT__script_init_session`, line 40182):
  - `send_message(type:int, data:string|buffer)`;
  - `set_client_type(str)`, which notifies the device of the client type
    (`RAAT__session_set_client_type`);
  - `message_handlers` and `shutdown_handlers`, tables of functions;
  - `remote_address`, a table `{family, ip, port}` (`FUN_001f1b40`).
**Module placement matters.** `buffer`, `stream` and `codec` are **not** fields of `raat`.
They are registered with `luaL_requiref(L, name, open, 1)`, which sets both a *global* of
that name and `package.loaded[name]` (`RAAT__script_init_buffer` line 37702,
`RAAT__script_init_stream` line 40440, `RAAT__script_init_codec` line 40580). `log`,
`info`, `session`, `platform`, `output`, `volume`, `source_selection`, `transport`,
`app_channel` and `codecs` are fields of the global `raat`.

- **`buffer`** (global), metatable `RAAT__ScriptBuffer` (`FUN_001d9200`,
  line 25858, table `0x5500c0`, 191 entries):
  - `new`, `ensure_capacity`;
  - `{get,set,read,write}_{int,uint}{8,16,32,64,ptr}_{le,be}[_array]`;
  - `float32`/`float64` le/be, `get/set/read/write_string`, `to_string`,
    `transform_copy`, `__tostring`.
  - Constants: `is_little_endian=true`, `is_big_endian=false`, `pointer_size=8`,
    `has_working_copy_method=true`.
  - A 32-bit ARM build would report `pointer_size=4`. **[inferred]**
- **`stream`** (global), metatable `RAAT__Stream` (`FUN_001f1d40`, line 40206;
  table `0x550d80`). It is the sample ring buffer between script and output thread.
  - `new(format, capacity_samples)` (`FUN_001f1db0`).
  - `write(stream_sample:int, gain:number, peak:number, data, nsamples)` (`FUN_001f21e0`,
    line 40395). The two numbers are the per-packet normalization `gain` and `peak` that the
    Core sends in `COMMAND_NORMALIZATION`. Both are float64 and default to 0.0
    (`script-4.lua:235-236`, `:291-295`, `:340-343`). They are stored as packet metadata.
    The only gain code in the C layer is the software-volume plugin's
    `RAAT__pcm_gain_*` path (`FUN_001ba970`, line 4967). Whether the ALSA path applies the
    per-packet gain was not traced (section 12).
  - `write_chmap(..., nsamples, chmap)`, `clear()`, `get_stats()`. Stats are `write_count`,
    `read_count`, `samples_in`, `samples_out`, `dropout_count`, `samples_dropped`,
    `overrun_count`, `samples_overrun`, `capacity_samples` and `fill_samples` (strings).
  - `has_write_chmap=true`. `nsamples` above the buffer size raises an error.
- **Stream format table** (`RAAT__unpack_stream_format` line 25735, `FUN_001ee480`
  line 38250):
  - `sample_type` is `"pcm"` or `"dsd"` on input. `pcm_float32` and `pcm_float64` can
    appear on output.
  - `sample_rate`, `bits_per_sample` and `channels` are ints.
  - `sample_subtype` is `"none"`, `"mqa"` or `"mqa_core"`.
  - `mqa_original_sample_rate` is optional.
- **`codec`** (global), metatable `RAAT__Codec` (table `0x550e00`): `new(name)` and
  `decode_to_stream(...)`. The list of supported codec names is `raat.codecs`
  (`RAAT__script_init_codec`). FLAC is the only
  codec (`RAAT__codec_flac_new`, strings `[codec/flac] ...`). A script may send FLAC on the
  wire and ask the device to decode it, so a native endpoint should provide FLAC decode.
  **[inferred]**
- **`raat.output`** (`RAAT__script_init_plugin_output`, line 38875). This is the core
  audio contract.
  - `is_supported`, `is_refresh_supported_formats_supported=true`,
    `is_get_output_delay_supported=true`.
  - `info`: a JSON string, or nil.
  - `supported_formats`: an array of format tables.
  - `message_handlers`: functions receiving JSON strings from the output, for example the
    signal path (section 8.6).
  - `setup(format, cb_table)` (`FUN_001ee7a0`, line 38344). It is asynchronous. Later the
    plugin calls `cb_table.on_setup(true, token:int)` or `cb_table.on_setup(false, errstr)`
    (`FUN_001ef360`, line 38820). It may also call `cb_table.on_output_lost(json|nil)`
    (`FUN_001ef1d0`, line 38763).
  - `teardown(token)` (`FUN_001ee380`, line 38207) frees the setup token.
  - `force_teardown([json])` (`FUN_001eee40`).
  - `start(token, start_time_ns, stream_sample, stream)` (`FUN_001eed10`, line 38572). The
    argument order is confirmed by the null plugin's slot-4 implementation (`FUN_001b88c0`,
    line 3676): arg 2 becomes the start deadline compared against `RC__now_ns`, and arg 3
    the first stream sample. It is only accepted in state "set up". Otherwise it fails
    with status 8001 or 8002 (`0x1f41`/`0x1f42`; presumably invalid token and invalid
    state).
  - `stop(token)` (`FUN_001eebb0`).
  - `get_local_time(token) -> ns` (`FUN_001eec10`). This is not raw `now`. In the null
    plugin (`FUN_001b9aa0`) it is `now - last_buffer_deadline + samples_to_ns(samples
    played)`, a clock that tracks playback position.
  - `set_remote_time(token, remote_minus_local_ns:number, reset:bool)` (`FUN_001eec80`).
    The plugin pairs the number with its own position clock, as in `get_local_time`, and
    passes both to drift correction (`FUN_001b8810`, line 3653).
  - `get_output_delay(token) -> ns|nil` (`FUN_001eedb0`).
  - `send_message(json_string)` (`FUN_001eeaa0`).
  - `refresh_supported_formats()` (`FUN_001ee620`).
  - It has a metatable with `__gc`.
- **`raat.volume`** (`RAAT__script_init_plugin_volume`, line 40012):
  - `is_supported`, `is_double_volume_supported=true`, `info` (JSON);
  - `state` is `{type, min, max, value, db_min, db_max, step, mute}`, where `type` is one
    of `none|number|db|incremental|hidden_number` (`FUN_001f1090`, line 39794);
  - `state_change_handlers`;
  - `set_volume(value:number)` (`FUN_001f1490`, line 39928), `set_mute(bool)`,
    `increment_volume(how)` (`"invalid value for 'how'"`), `toggle_mute()`. Missing
    capabilities raise `"... is not implemented"`.
- **`raat.source_selection`**, **`raat.transport`**, **`raat.app_channel`**:
  `RAAT__script_init_plugin_source_selection` (line 39350), `_transport` (line 39650) and
  `_app_channel` (line 38160). These are optional plugins, and RoonBridge never installs
  them, so they expose `is_supported=false`. Their full surface (`request_source[_v2]`,
  `request_standby`, `update_status`, `update_artwork`, `send_message` and others) is only
  needed for devices with inputs, a display or vendor channels.
- **luv** is fully exposed (`uv = require('luv')`, tables `0x551180`-`0x552580` in
  `native/lua_reg_tables.txt`). The script can open UDP and TCP sockets, timers and threads
  through it.

**Threading model [verified].** Each session runs its Lua VM on a dedicated thread with its
own libuv loop (`RAAT__session_start`, line 23402). Plugin callbacks from audio threads are
marshalled onto that loop with `RAAT__session_post`, an async handle (for example
`FUN_001ee900`/`FUN_001ee8b0`).

## 8. Audio path (C layer)

### 8.1 Output enumeration and description [verified]

- **Enumeration.** The Linux platform layer (`FUN_001c7ce0`, line 13525) walks ALSA cards
  and PCM devices. It names them `hw:CARD=<id>,DEV=<n>` (line 13944) and reads several
  other sources:
  - `/proc/asound/cardN/usbid` and the USB sysfs `idVendor`/`manufacturer`;
  - HDMI ELD (`" on HDMI"` names and `monitor_name`);
  - `/roon/sys/image_info`, for ROCK and Nucleus.
- **Environment overrides:**
  - `RAATSERVER_ALSA_BLACKLIST` (`card,dev;...`);
  - `RAATSERVER_ALSA_NAME_hw_<card>_<dev>`.
- **Probing.** It probes formats by opening the PCM
  (`[raatmanager/linux] [%s] supports PCM format %d/%d/%d`).
- **Description.** Each output becomes the `<device>` object from section 5.2. Its
  `config` (from the Core, persisted) drives `RAAT__wrap_new`:
  - `output.type` is `"alsa"` or `"null"`;
  - `volume.type` is `"alsa"`, `"software"` or `"null"`, with a fallback to no device
    volume (lines 2930, 2943).

### 8.2 ALSA output config keys [verified key names]

The keys are read in `RAAT__alsa_output_plugin_new` (line 10970) and
`FUN_001bc990` (setup, line 6299):

- `device`
- `supported_formats[]` (`sample_type`, `sample_rate`, `bits_per_sample`, `channels`)
- `max_pcm_rate`, `max_dsd_rate`
- `dsd_mode`: `none|native|dop|dcs|native_or_dop|native_or_dcs|dop_or_native|dcs_or_native`
- `buffer_duration`
- `resync_delay`
- `sync_offset_ns[]`, per rate and subtype
- `signal_path[]`, entries with an optional `condition {sample_rate,bits_per_sample,channels}`
- `force_max_volume`
- `disable_mqa_usb_device_support`
- `lost_action`
- `skip_startup_device_check`, `disable_usb_hw_info`

### 8.3 Format negotiation and setup [verified]

- The plugin's `supported_formats` come from config if they are hardcoded, else from ALSA
  probing (`[output/alsa] probing formats`).
- `setup(format)`:
  - It opens the PCM with `snd_pcm_hw_params_set_access`, `_format`, `_rate` and
    `_channels` set exactly. If the exact channel count fails it falls back to
    `set_channels_last`.
  - It has a "prefer larger samples" switch for choosing the ALSA container format
    (`prefer larger samples = %d` at lines 7250 and 7410). The exact containers it picks,
    for example S32 versus S24_3LE, were **[not verified]**.
  - Periods and buffer use `_set_periods_near` and `_set_buffer_size_near` from
    `buffer_duration` (`[ALSA] ... Requesting %d periods`).
  - A format outside the list fails with `RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED`,
    which reaches Lua as `on_setup(false, "...")`.
- **The plugin never resamples.** The Core picks a rate from `supported_formats`, so
  bit-perfect native-rate output only needs a correct list.
- **Declining DSD.** Never list `sample_type="dsd"` in `supported_formats` and report
  `max_dsd_rate=0` / `dsd_mode="none"`. The Core then converts DSD to PCM itself.
  **[inferred from the format filter; DSD paths were not analysed further]**

### 8.4 Start, timing and clock [verified, from the structurally identical null output `FUN_001b8970` line 3700, and ALSA `FUN_001c31e0` line 10550]

- **Clock.** The time base is `CLOCK_MONOTONIC_RAW` in ns (`RC__now_ns`, line 60392,
  `clock_gettime(4)`). Start deadlines are in that base. `get_local_time` returns a
  playback-position clock derived from it (section 7).
- **Start.** `start(token, start_time_ns, stream_sample, stream)` arms playback. The
  output thread keeps writing silence until `now + ns_per_buf > start_time_ns`. It then
  starts reading the stream at `stream_sample`, padding or skipping samples by the exact
  difference between `now` and `start_time_ns` (log
  `starting playback: now (...) + ns_per_buf(...) = ... > ... streamsample=...`).
  - Silence is `0x00` for PCM and `0x69` for DSD.
  - The output keeps `stream` referenced with `RAAT__stream_incref`/`decref`.
- **Clock sync.** The script passes remote-clock offset observations with
  `set_remote_time(token, offset_ns, reset)`. These go to
  `RAAT__drift_correction_set_remote_time` (line 18372). `remote = local + offset`, and
  `reset=true` re-bases the clock.
- **Correction.** `RAAT__drift_correction_compute_correction` (line 18444) averages the
  remote-minus-local drift over a window. It returns a per-buffer sample correction, which
  is applied by `RAAT__read_stream_with_drift_correction` (line 19133) as inserted or
  dropped samples, not resampling. Inserted samples are the average of their neighbours
  plus `RAAT__dither()` (around line 19594-19640), so output is not bit-identical while a
  correction is being applied.
- **Bit-perfect.** For a single-zone, bit-perfect endpoint whose DAC is the clock master,
  the expectation is that the Core paces to `get_local_time`, so corrections stay at zero.
  **[inferred; who is master is decided by the script]**
- **Faults.** Underruns log `dropout of %d samples` and overruns log
  `buffer overrun. discarding`.
- **Delay.** `get_output_delay` reports the hardware pipeline delay in ns. Configurable
  `sync_offset_ns` adds to it.

### 8.5 Stop, flush, seek [verified for the C primitives; how they are used is not derivable]

The C primitives are `stop(token)`, `stream:clear()`, `teardown(token)`, `force_teardown()`
and a new `start(...)` with a new `stream_sample`. How seek and flush map onto these is
decided by the Core's script.

### 8.6 Volume, mute and bit-perfect signalling [verified]

- **Hardware volume.** `alsa` volume (`RAAT__alsa_volume_plugin_new` line 12769,
  `FUN_001c5650` line 11873) uses an ALSA mixer element chosen by `index`/`name`, or
  auto-searched. Its `mode` is `number` or `db`, it falls back to `number` when the dB range
  is unavailable, and it has `db_min`, `db_max` and `db_step`. Mute uses the playback
  switch.
- **Software volume.** `software` volume (`RAAT__software_volume_plugin_new` line 5162)
  applies gain in the output (`RAAT__pcm_gain_16/24/32`) and has `max_attenuation`. It
  reports `requires_external_persistence`, which means the Core keeps the level.
- **Fixed volume.** `RAAT__wrap_new` accepts only `volume.type` `"alsa"` or `"software"`.
  It also accepts an absent `volume` key. Any other type, `"null"` included, logs
  `unknown volume type ... running without device volume` (lines 2895-2945). In every
  such case no volume plugin is installed and `raat.volume.is_supported=false`. The
  library also contains `RAAT__null_volume_plugin_new`, but RoonBridge's wrapper never
  uses it. The Core then shows the zone as fixed volume or offers its own DSP volume.
  **[the UI mapping is inferred]**
- **Signal path.** After setup, the output sends a JSON message
  `{"signal_path":[...]}` through `RAAT__output_message_listeners_invoke` (line 20823) into
  `raat.output.message_handlers` (`FUN_001b9b30` line 4385, `FUN_001bbd80` line 5804). The
  elements are:
  - any config `signal_path` entries whose `condition` matches the current format;
  - `{type:"dsd_encapsulate",...}` for DoP or DCS;
  - always `{"type":"output","method":"alsa","quality":"lossless","alsa_device":...}`.
- Software volume prepends `{"type":"digital_volume","gain":dB,"is_muted":..,
  "quality": gain==0 ? "lossless" : "high","is_passthrough": gain==0}` (`FUN_001bab00`,
  line 4988).
- **Bit-perfect is signalled** by every element having `quality:"lossless"`.

## 9. Things deliberately not done

- **`raat.dat`** is the Core's script bundle (section 1.2). It was not decrypted or
  decompressed. The scripts were obtained the legitimate way, as plaintext `load_script`
  JSON a Core sent to an endpoint Noa owns.
- Encryption and DRM are not involved in the RAAT path of this binary. Script signing is
  verify-only, with a public key. Nothing needed bypassing.
- MQA USB (hidapi/libusb) and the DSD/DoP/DCS packers were noted and not analysed.

## 10. Resource-management obligations toward the Core

Roon warned that misuse can leak resources on the Core. These are the endpoint-side rules
the reference implementation follows:

1. **Exactly one final response per request.** Every LL request with an id other than
   `0xFFFFFFFF` gets exactly one `is_final=1` response. Duplicates are refused and logged as
   `multiple final responses on cx` (`RNET__json_request_context_respond`, line 135312).
   The `load_script` reply is deferred until the script's top level has finished.
2. **Long-lived subscriptions are closed with a final response.**
   - `enumerate_devices` and `enable_device` stay open with non-final responses.
   - `cancel_enumerate_devices` and `disable_device` must end them with a final
     `{"status":"Canceled"}` on the *original* request id, then answer the cancel itself (the
     `cancel_enumerate_devices` and `disable_device` branches of `FUN_001b4cb0`). On
     manager shutdown, every open subscription also gets a final `Canceled`
     (`RAAT__manager_delete` lines 2505-2506, via `FUN_001b37e0`/`FUN_001b3760` at
     lines 715-758).
3. **Disconnect cleanup.**
   - When the manager's TCP client goes away, enumerate subscriptions are dropped through
     their gone handler (`FUN_00279040` line 135249, `FUN_001b3700` line 697).
   - `enable_device` subscriptions have **no** gone handler in this build: a device stays
     enabled until `disable_device`, even if the Core disconnected **[verified; this looks
     intentional, so outputs survive Core restarts]**.
   - When a device-server client disconnects, times out, sends a bad frame or hits a Lua
     error, the endpoint runs these steps in order:
     1. stop reading;
     2. delete the session;
     3. stop the Lua loop;
     4. run every `raat.session.shutdown_handlers` function once (`FUN_001d56c0`
        line 23278, `RAAT__session_delete` line 23365);
     5. close the VM.

     The script's shutdown handlers are where the output is torn down.
4. **Setup tokens are owned and released.**
   - Each `setup` creates a ref-counted token object, and only one is active at a time. A
     new setup "kicks off" the old output, or loses the race (`lost the race`).
   - `teardown(token)` and `on_output_lost` clear it (`FUN_001ee380`, `FUN_001ef1d0`).
   - A stale token yields `RAAT__OUTPUT_PLUGIN_STATUS_INVALID_TOKEN`.
5. **Keepalive.** Honour `LL_BEGIN_KEEPALIVE` by sending `0x80000003` every `interval_ms`.
   Drop the connection if nothing arrives for `timeout_ms`. Stop on `LL_END_KEEPALIVE`.
6. **Report output loss promptly.** If the ALSA device disappears
   (`[watch/alsa] device %s lost`), call `on_output_lost`. Then push `DeviceChanged` or
   `DeviceRemoved` on enumerate subscriptions.
7. **Script errors.** Any Lua error inside a handler tears down the whole client connection
   (`RAAT__session_lua_pcall` line 23221 calls the failure callback; `FUN_001d4200`
   line 22482). Do not swallow errors in a way that leaves the Core with a half-open session.

## 11. Minimal native endpoint checklist (one ALSA output, PCM only, bit-perfect)

Revised with the capture. Section numbers point at the details.

1. **Identity.** Persist a random `unique_id` GUID. Report `machine_id` (for example
   `/etc/machine-id` formatted as a GUID), `machine_name`, `os_version`, `vendor` and
   `model`.
2. **SOOD responder** (section 4). Listen on UDP 9003, joined to 239.255.90.90 on every
   interface.
   - Answer only `Q` packets whose `service_id` is `d7634b85-8190-470f-aa51-6cb5538dc1b9`.
   - Reply unicast `R`, echoing `_tid` and honouring `_replyaddr`/`_replyport`.
   - Include `raat_version`, `protocol_version=1`, `config_version=1`, `is_dev=0`,
     `tcp_port`, `unique_id` and the identity keys.
   - The `raat_version` value the Core expects is unsettled. The analysed x64 build sends
     `1.1.48`, and the R26 that works with Noa's Core reports `1.1.38` (section 13).
   - Leave out `code_signing_keys` unless the endpoint also verifies signatures
     (section 13.2).
3. **Manager JSON-RPC** over LL framing (sections 5.1, 5.2, 13.1) on a TCP port in
   9200-9250. The Core used 9200.
   - Accept the Core's `LL_BEGIN_KEEPALIVE(2000, 10000)` and its `0x80000003` pings.
   - `enumerate_devices{subscription_id}`: reply non-final with `devices`, then push
     `DeviceAdded/Removed/Changed`.
   - `enable_device{device_id, subscription_id}`: reply non-final `Success`, then start the
     device server and include its `discovery_data.tcp_port` in the next device update.
   - Also implement `disable_device`, `cancel_enumerate_devices`, `retry_device`,
     `refresh` and `get/set_device_config`, with the final and non-final rules of
     section 10.
   - Use `device_id = "hw:CARD=<id>,DEV=<n>"`, the format the Core sent
     (`frames.jsonl:6`).
   - Model the `<device>` object on the observed one (section 13.1): `device_id`,
     `type:"alsa"`, `name`, `vendor`, `usb_id`, and
     `config{unique_id, external_config:{}, output{type:"alsa", device, name, dsd_mode},
     volume{...}}`.
   - After enable, push `DeviceChanged` on the enumerate subscription, carrying
     `discovery_data{tcp_port, unique_id, raat_version, protocol_version:"3", vendor,
     model, version}`.
   - Set `dsd_mode` to `"none"` for PCM only. The R26 sends `"native"`.
4. **Device LL server** (sections 5.3, 5.4, 13.2) on an ephemeral TCP port, IPv4.
   - Handle keepalive, `get_info`, `get_log`/`clear_log` and `load_script`.
   - Preload the three modules (`base`, `dkjson`, `protocol`) and execute `roon_tcp`.
   - Every load needs its deferred final reply.
   - **Signatures.** The Core sent `signature:null` to an endpoint advertising no keys,
     and that endpoint answered `Success` (section 13.2). Do the same: advertise no keys
     and accept unsigned scripts. If a `signature` is present, verify it with Ed25519
     against the `"Roon"` key.
   - Route frame types below `0x80000000` to and from `raat.session` unchanged. Section
     13.3 describes the inner request/response layer, which the script implements, not the
     C code.
5. **Lua 5.3 + luv**, one VM and one thread per connection.
   - Provide everything listed in section 13.10. That list is what the scripts call, and
     it is smaller than the full section 7 surface.
   - Watch the luv extensions the scripts probe for: `read_start_noalloc`,
     `udp_recv_start_noalloc` and `recv_buffer_size`. The scripts fall back when the first
     two are missing.
   - Set `raat.transport`, `raat.source_selection` and `raat.app_channel` to
     `{is_supported=false}`. Then the multicast bus (section 13.9) stays off.
   - Hook or override `os.exit`. The `force_exit` request calls it (section 13.11).
   - **Memory.** The script allocates a `stream` of `2 * buffer_size * sample_rate`
     frames (`script-4.lua:1275-1278`). `buffer_size` is a Core-chosen number of seconds:
     10 in capture3, of which at most about 5.4 s was ever in flight (section 14.3). At 192 kHz, 2 ch and 32 bits, each second of
     `buffer_size` costs 3 MB of ring buffer. Budget for it, and cap `supported_formats`
     if RAM is tight.
6. **Output plugin** (sections 7, 8, 13.4-13.8).
   - `supported_formats`: only the exact PCM rate, bit and channel combinations the DAC
     takes natively, with `sample_type="pcm"`. List no DSD and no float.
   - `raat.codecs`: leave it nil, as the R26 does: its `info` reply has no `codecs` key
     (section 13.4). That the Core then never sends `wire_codec` is **[inferred]**. If
     FLAC must be supported, `codec.new(name, format)` and
     `decode_to_stream(stream, sample, gain, peak, buf, nsamples)` are needed.
   - `raat.output.info`: a JSON string. The R26 shape is
     `{alsa_device:{name,id,longname,components,usbid,driver,mixername}, config:{...}}`.
   - `raat.platform.uname` (`sysname`, `nodename`, `release`, `version`, `machine`) is
     reported to the Core.
   - `setup(format, {on_setup, on_output_lost})`: open `hw:` at the exact rate, format and
     channels, then call `on_setup(true, token)`. On failure use one of the status strings
     `RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_IN_USE`, `_DEVICE_INIT_FAILED` or
     `_DEVICE_OPEN_FAILED`, so that the script maps it to a proper error
     (`script-4.lua:972-982`).
   - `start(token, time_ns, stream_sample, stream)` and `stop(token)`.
   - `get_local_time(token)` and `get_output_delay(token)` must work from `SETUP` onwards.
     The clock responder calls them on every `RAATCLKQ`.
   - Drift correction behind `set_remote_time(token, offset_ns, reset)`. For a lone zone,
     never insert or drop samples, so the output stays bit-perfect.
   - `teardown(token)`.
   - During setup, send `{"signal_path":[{"type":"output","method":"alsa","quality":"lossless","alsa_device":{...card info...}}]}`
     into `raat.output.message_handlers`, before `on_setup` fires. It reaches the Core
     as `OutputMessage`, ahead of the setup `Success` (section 14.2).
7. **Audio TCP listener and clock UDP socket.** The script opens both itself through luv.
   The endpoint only needs working luv TCP and UDP, plus a way to pass the payload into
   `stream:write`, ideally without copying.
   - Payload: interleaved little-endian signed PCM, `bits_per_sample/8` bytes per sample
     (section 13.6).
   - Write it to ALSA unmodified. Do not apply the per-packet `gain`.
8. **Fixed volume.** `raat.volume = {is_supported=false}`. `get_controls` then returns no
   volume, and the Core treats the zone as fixed or uses DSP volume. For hardware volume,
   provide `state` and `set_volume`/`set_mute` (section 13.8).
9. **Teardown discipline** (section 10). On disconnect, timeout or Lua error, run
   `shutdown_handlers`: the script tears down the output and closes its sockets. Then
   close the PCM and free the token and stream, and report the change to manager
   subscribers.

## 12. Open questions

A two-way playback capture now exists (capture3, section 14). It settles, for one
44.1 kHz/16-bit zone on its own: the `setup` format (no `wire_codec`), `stream`
`buffer_size`/`ready_threshold`, `start` (`min_offset` only, no `time`), that a lone
zone gets no `sync`, the audio command order and chunk size, that no
`COMMAND_NORMALIZATION` is sent, `CHMAP` -1, how seek, pause and track change map onto
the primitives, the clock query rate and the reported delay. The list below is kept
as it was, with what capture3 answered marked **[c3]**; what is not marked is still
open. Still unseen: format changes, high rates, DSD, grouped zones, a resume within the
Core's 5 s pause window, and natural (gapless) track ends.

These still need a **playback capture**, in both directions (Core to endpoint *and*
endpoint to Core), taken while a track plays, seeks, pauses and changes format:

- **Whether the Core signs scripts for endpoints that advertise `code_signing_keys`**
  (1.1.48 builds). This needs a capture against a current x64 or arm RoonBridge. It is not
  needed for a native endpoint that advertises no keys.
- **Version matching.** Which `raat_version` a native endpoint should advertise
  (`1.1.38` versus `1.1.48`), and whether the Core selects a different script set by
  version. The four scripts are identical in both captures, both against 1.1.38.
- **The values the Core sends:**
  - in `setup`: the format, and whether `wire_codec` is set when `codecs` is non-empty;
    **[c3: plain PCM format plus `sample_subtype:"none"`, no `wire_codec` with `codecs`
    nil; the non-empty case is still open]**
  - in `stream`: `buffer_size`, `ready_threshold`, `first_seq`, `stream_id`;
    **[c3: 10, 0.2, -1, a large counter; also `nak_port:-1`]**
  - in `start`: `time` versus `min_offset`; **[c3: `min_offset` only]**
  - in `sync`: `host`/`port`, which tells who is clock master for a single zone.
    **[c3: no `sync` at all for a lone zone; grouped zones still open]**
- **On the audio TCP stream:** the command order, the `DATA` chunk size, whether
  `COMMAND_NORMALIZATION` carries a non-zero gain for bit-perfect playback, and the
  `CHMAP` values. **[c3: section 14.3; no NORMALIZATION was sent; whether it appears
  with volume leveling on is open]**
- **Seek, pause, flush and track change:** whether the Core uses
  `stop` + `start(stream_sample)`, `end_stream` + `stream`, or a new `setup` for each.
  **[c3: section 14.4]**
- **The clock exchange:** the rate of `RAATCLKQ` queries from the Core, and how much
  output delay it expects. **[c3: section 14.5]**
- **Whether the ALSA output applies the per-packet `gain`** from `stream:write`
  (static trace not done).
- **Version checks.** How strictly the Core checks `vendor`, `model` and `version`
  (`"N/A"` in RoonBridge) and `protocol_version`.
- **The `config_info` schema and the full `config` keys** in
  `get_device_config`/`set_device_config`. The observed `config` holds only `unique_id`,
  `external_config`, `output` and `volume`.
- **The `usb_id` field.** It appears in the 1.1.38 `<device>` object but was not found in
  the 1.1.48 builder.
- **Whether the native manager's unsolicited announce is a `Q` packet.** This also needs
  a capture of SOOD traffic, which this one lacks.
- **The internet-discovery `AuthProvider`** used by RAATServer. This does not matter for
  LAN operation.
- **ARM builds** (`pointer_size`, rate limits). Not checked.

## 13. Session protocol implemented by the Core's scripts

Sources, both private and both taken across a bridge restart. Each one has a
`decoded/frames.jsonl` (every LL frame) and `decoded/script-1..4.lua` (the four
`load_script` payloads, identical in both captures):

- **`capture/`** (first capture). It holds only the Core-to-endpoint direction: 205 TCP
  segments, all from 192.0.2.19. The capture tool was bound to `ETH_P_IP`, which does
  not see local TX.
- **`capture2/`** (second capture). It has **both directions**: 232 segments, including
  for example 43 segments with 1,666 payload bytes from device port 45615 and 49 segments
  from manager port 9200.
  - Frame numbers below written `c2:N` are lines of `capture2/decoded/frames.jsonl`.
  - The decoder truncates session-message bodies there (`session_head`), so full bodies
    were checked by re-assembling the TCP streams from `capture2/raat.pcap` with a scratch
    script.
  - The manager connection was already open when the capture started. Its
    `enumerate_devices` request and `LL_BEGIN_KEEPALIVE` are therefore only in `capture/`,
    but the replies are in `capture2/`.

Neither capture has SOOD, UDP, audio or clock traffic. Both stop after script load and the
first four session requests, so everything below about playback comes from the script
code, not from observed traffic.

**The captured endpoint is not the build analysed statically [verified].** The device's
`info` reply reports `platform.uname`:

- `machine` = `armv7l`, `nodename` = `Gustard-R26`, `release` = `4.9.84`;
- `discovery_data.raat_version` = **`1.1.38`** (`c2:6`, `c2:66`).

The x64 `libraatmanager.so` analysed in sections 1-10 hard-codes `1.1.48`
(`RAAT__info_new`, line 20261). So the endpoint on 192.0.2.46 is the Gustard R26's own
RAAT 1.1.38 stack. It speaks the same RoonBridge-style manager/device protocol (port
9200, `"N/A"` vendor, model and version), but it is a different and older build.
Observations below are from 1.1.38. Static citations are from 1.1.48.

The scripts are Roon's code and are described here, not reproduced. `script-2.lua` is the
third-party dkjson 2.5 JSON library by David Kolf (MIT licence, `script-2.lua:8-30`).

### 13.1 Manager traffic seen

| frames.jsonl | Core sends | Notes |
|---|---|---|
| :3 | `LL_BEGIN_KEEPALIVE` interval 2000 ms, timeout 10000 ms | Sent on connect, port 9200. The same values were used on the device server (:37, `c2:30`). |
| :4, :7… | `0x80000003` with empty body, about every 2 s | **The Core pings too.** So both sides send pings, and the endpoint's inbound timeout is fed by them. |
| :5 | `{"request":"enumerate_devices","subscription_id":"0"}`, req_id 1 | |
| :6 | `{"request":"enable_device","device_id":"hw:CARD=G20,DEV=0","subscription_id":"22"}`, req_id 2 | Confirms the device id format `hw:CARD=<alsa card id>,DEV=<n>`. Subscription ids are Core-chosen strings. |
| :1-2 | pings from earlier sockets, to the old device port 34845 | The device-server port changed from 34845 to 46427 across the restart: ephemeral, as in section 5.3. Several zero-payload connects to 9200 are the Core's reconnect attempts. |

**Manager replies observed** (`capture2/`, rid 1 is `enumerate_devices`, rid 2 is
`enable_device{device_id:"hw:CARD=G20,DEV=0", subscription_id:"23"}`):

| c2 | Reply | Body |
|---|---|---|
| :5 | rid 1, **non-final** | `{status:"Success", devices:[<device>]}` |
| :6 | rid 1, **non-final** | `{status:"DeviceChanged", device:<device + discovery_data>}`. The enable caused it, and it is pushed on the *enumerate* subscription. |
| :7 | rid 2, **non-final** | `{status:"Success"}`. The enable subscription stays open. |

This matches section 5.2 and section 10 item 2: both subscriptions stay open with
non-final replies.

The **observed `<device>` object** (1.1.38) has:

- `device_id`: `"hw:CARD=G20,DEV=0"`.
- `type`: `"alsa"`.
- `name`: `"Gustard USB Audio 2.0"`, and `vendor`: `"Gustard"`. Both come from the USB
  descriptors.
- `usb_id`: `"20b1:3033"`, as `vid:pid` in hex. This key is not in the 1.1.48
  `FUN_001b3360` key list. Either it lives elsewhere in that build or it was dropped
  **[unresolved]**.
- `config`, which has:
  - `unique_id`: a GUID. It is the same value that later appears in `discovery_data` and
    `raat.info`.
  - `external_config`: `{}`.
  - `output`: `{type:"alsa", device:"hw:CARD=G20,DEV=0", name, dsd_mode:"native"}`.
  - `volume`: `{type:"alsa", device:"hw:CARD=G20,DEV=0"}`.
- `discovery_data`, added once the device is enabled: `{tcp_port:45615, unique_id,
  raat_version:"1.1.38", protocol_version:"3", vendor:"N/A", model:"N/A",
  version:"N/A"}`. **There is no `code_signing_keys`** (see section 13.2).

Keys from section 5.2 that did not appear: `error_message`, `interface_name`, `model`,
`is_system_output`, `auto_enable`, `no_hardware_volume` and `auto_name`. The builder emits
those only when they are set, which matches the conditional `json_object_set_new` calls
in `FUN_001b3360`.

### 13.2 Script load

The Core connects to the device port it learned from `discovery_data.tcp_port`. It sends
`LL_BEGIN_KEEPALIVE(2000, 10000)` and then four `load_script` requests. All four use
req_id 1 (`frames.jsonl:39-42`):

| # | `name` | `module` | Role |
|---|---|---|---|
| 1 | `raat.dat:base.lua` | `base` | Subscription-table helpers (`subscribe`/`unsubscribe`, keyed by `request.subscription`) and string utilities (`script-1.lua:5-46`) |
| 2 | `raat.dat:dkjson.lua` | `dkjson` | JSON encoder and decoder |
| 3 | `raat.dat:protocol.lua` | `protocol` | Request/response layer over session messages (section 13.3) |
| 4 | `raat.dat:roon_tcp.lua` | none, so the chunk is executed | The endpoint logic. It calls `go()` at load (`script-4.lua:1407`) and registers its shutdown handler (`:1406`). |

**Signatures: resolved for this endpoint [verified].** All four requests carry
`"keypair": null, "signature": null` (`c2:32-35`), and all four got final
`{"status":"Success"}` on rid 1 (`c2:62-65`). The cause is that the captured 1.1.38
endpoint advertises **no `code_signing_keys`** in its `discovery_data` (`c2:6`). A device
with no registered keys accepts any script:
`RAAT__device_check_code_signature` returns true when the key count is 0 (line 16364).
That is the no-keys branch of the same check in 1.1.48.

- The analysed 1.1.48 x64 build does register the `"Roon"` key (`RAAT__wrap_new`,
  line 2824). It adds the key to `discovery_data` (`RAAT__wrap_get_discovery_data`,
  line 2736) and in this state would answer an unsigned script with
  `InvalidCodeSignature`. Presumably the Core signs only for endpoints that advertise
  keys **[inferred; needs a capture against a 1.1.48 endpoint]**.
- **For a native endpoint:** advertise no `code_signing_keys` and accept the plaintext
  scripts, as the R26's 1.1.38 stack does. This needs no secret and bypasses nothing. The
  endpoint simply does not ask for signatures. Alternatively, advertise the `"Roon"` key
  and verify, which is safer but depends on the inferred Core behaviour.

**Load replies.** The four `load_script` requests are pipelined on the same rid (1), and
the four replies come back in order, each final (`c2:62-65`). After them come the session
replies to the requests the Core had already queued (`c2:66-68`).

**Ordering.** The modules must be preloaded before `roon_tcp` runs, because its top level
`require`s them. The device answers each `load_script` once its chunk has been handled
(section 5.3).

### 13.3 Session message layer (`protocol.lua`)

Each LL frame with type below `0x80000000` is one session message. The LL type *is* the
session message type (`frames.jsonl:43-46` carry LL type 1).

| type | Name | Body |
|---|---|---|
| 1 | REQUEST (Core → endpoint) | `int32 BE rid` + JSON object (`script-3.lua:50-59`) |
| 2 | RESPONSE (endpoint → Core) | `int32 BE rid` + `uint8 is_final` (1 final, 0 non-final) + JSON (`script-3.lua:23-40`) |
| 3 | ARTWORK (Core → endpoint) | A raw image blob, stashed until the next `update_artwork` request (`script-3.lua:60-62`) |

- The layout mirrors the LL control layer of section 5.1, one level up. The `rid` space
  belongs to the script. The Core used rids 2, 3, 4 and 5 for `info`, `set_client_type`,
  `subscribe_transport` and `subscribe_controls` (`frames.jsonl:43-46`).
- If a request has `"quiet": true`, logging is suppressed and every response echoes
  `quiet=true` (`script-3.lua:15-35`).
- An unknown `request` gets final `{"status":"NotSupported"}` (`script-4.lua:1397-1404`).
- Every request handler must end with exactly one final response, the same rule as
  section 10. Subscriptions stay open with non-final responses and have no explicit end
  except `unsubscribe_*` (`script-1.lua:14-21`). The subscription key is
  `request.subscription`, or a generated one when that is absent (`script-1.lua:5-12`).

### 13.4 Requests the endpoint script serves

From the dispatcher at `script-4.lua:1369-1396`:

| request | Fields used | Responses |
|---|---|---|
| `info` | none | Final `Success` with the fields below (`:774-801`). |
| `set_client_type` | `client_type`. The Core sent `"Roon"` (`frames.jsonl:44`). | Calls `raat.session.set_client_type`, then final `Success` (`:1210-1215`). |
| `get_controls` | none | Final `Success` with `controls` (section 13.8). |
| `subscribe_controls` | `controller_id` (the Core sent a GUID, `frames.jsonl:46`), `unique_id` | Non-final `{Success, action:"Changed", controls}`, re-sent on every volume or source change. After a random 200-500 ms it may take transport ownership (`:826-840`). |
| `unsubscribe_controls`, `subscribe_transport`, `unsubscribe_transport`, `subscribe_app_channel`, `unsubscribe_app_channel` | `subscription` | A subscribe sends **no** response until there is an event. An unsubscribe answers final `Success` or `NotFound` (`:810-844`, `script-1.lua`). |
| `update_volume` | `value` \| `increment` \| `mute` \| `toggle_mute` | Final `Success`. If volume is unsupported it returns without a response (`:928-970`). See section 13.8. |
| `increment_volume` | none | The handler `req_increment_volume` is undefined, so the table entry is nil and the reply is `NotSupported` (`:1380`). |
| `setup` | `format{sample_type,sample_rate,bits_per_sample,channels}`, `wire_codec` | Section 13.4.1. |
| `teardown` | none | Final `InvalidState` without a setup. Otherwise it ends the stream, calls `output.teardown`, sends final `Teardown` on the *setup* context and returns no final reply of its own (`:1090-1117`) **[the latter is verified script behaviour]**. |
| `stream` | `first_seq`, `stream_id`, `buffer_size` (seconds), `ready_threshold` (fraction) | Section 13.4.1. |
| `start` | `time` (endpoint clock ns, optional), `stream_sample`, `min_offset` (ns, used when there is no `time`) | Final `{Success, time}`. Allowed from `BUFFERING`, `READY` or `STOPPED`, otherwise `InvalidState` (`:1298-1339`). |
| `stop` | none | Final `Success`. Only allowed from `PLAYING` (`:1341-1364`). |
| `end_stream` | none | Stops if playing and cleans up the stream, then final `Success` (`:1221-1248`). |
| `sync` | `host`, `port`, `new_source` | Clock sync (section 13.7). Final `Success`, `Timeout` or `InvalidState`. |
| `refresh_supported_formats` | none | Final `Changed{supported_formats}` or `NotChanged` (`:755-770`). |
| `update_transport`, `update_artwork`, `request_source`, `request_standby`, `app_channel_send_message` | | Only meaningful with transport, source-selection or app-channel plugins. Unsupported ones reply `NotSupported`, except for the hazard in section 13.11. |
| `echo` | anything | The request echoed back with `status=Success` (`:616-620`). |
| `force_exit` | none | `os.exit(1)` (`:1217-1219`). |

The **`info` reply** (`:774-801`) contains:

- `info`: `raat.info`;
- `platform`: `raat.platform`;
- `output.supported_formats`: compressed as a string (`compress`, `:735-753`);
- `output.info`;
- `transport.{is_supported, is_update_status_supported, is_update_artwork_supported, info}`;
- `volume.{is_supported, info}`;
- `source_selection.{is_supported, info}`;
- `flags.has_write_chmap`;
- `codecs`: `raat.codecs`.

**Format negotiation.** The Core learns the formats from this one string. Each
`rate/bits` pair lists its channel counts joined by `|`, and the pairs are joined by `,`.
For example `44100/16/2,96000/24/2|6`. The Core then picks a format for `setup`.
**[the string format is verified; the Core's choice rule is not derivable]**

**Session replies observed** (`capture2`, reassembled from the pcap; LL type 2,
`c2:66-68`):

- **`info`** (rid 2): final `Success`. The R26's string lists 35 entries
  (rate/bits/channels):
  - PCM at 44.1 kHz to 768 kHz, at 16, 24 and 32 bits, each with `1|2` channels;
  - DSD as entries with `bits_per_sample = 1` and the DSD bit rate as the "rate":
    `2822400/1/1|2`, `5644800/1/1|2`, `11289600/1/1|2` and `22579200/1/1|2`.

  The compressed string **drops `sample_type`**. The Core can tell DSD only from bits = 1
  **[inferred]**.
  - **For a PCM-only endpoint:** no `/1/` entries, and no rates or bit depths the DAC
    does not take natively.
  - The entries are unordered, because they come from a Lua `pairs` walk.
- **Other `info` fields observed.**
  - `info` is `{unique_id}` only. On 1.1.38, `raat.info` carries just the unique id. On
    1.1.48 it would be the whole dictionary (`RAAT__script_init_info`, line 37723).
  - `platform` is `{os:"linux", uname:{sysname, nodename, release, version, machine}}`.
  - `output.info` is `{alsa_device:{name, id, longname, components, usbid, driver,
    mixername}, config:{name, dsd_mode, type, device}}`.
  - `volume`, `transport` and `source_selection` are each
    `{is_supported:false, info:[]}`, and `flags` is `{has_write_chmap:true}`.
  - There is **no `codecs` key**, so `raat.codecs` was nil on 1.1.38. An endpoint can omit
    it.
  - An empty Lua table serialises as `[]` (dkjson), for example `info:[]`. The Core
    accepts that.
  - This R26 runs with **no device volume** even though its config says
    `volume.type:"alsa"`, which is consistent with the "running without device volume"
    fallback of section 8.6.
- **`set_client_type`** (rid 3): final `{status:"Success"}`.
- **`subscribe_transport`** (rid 4): **no reply**, as the script predicts (section
  13.4).
- **`subscribe_controls`** (rid 5): non-final `{status:"Success", action:"Changed",
  controls:[]}`. Here `controls` is an empty table, because volume and source selection
  are unsupported.

#### 13.4.1 Setup, stream and start lifecycle

The state machine is `IDLE → SETUP → BUFFERING → READY → PLAYING ⇄ STOPPED`
(`script-4.lua:24-29`, `:33-49`). Two request contexts stay open while it runs.

**`setup`** (`:984-1056`):

1. It validates the format. Only `pcm`, `dsd`, `pcm_float32` and `pcm_float64` are
   accepted, otherwise the reply is `InvalidArgument` (`:52-83`). Note that the *raw*
   `r.format` is what goes to `raat.output.setup`.
2. Any previous `current` is stopped, cleaned and torn down, and its setup context gets
   final `Teardown`.
3. It calls `raat.output.setup(format, {on_setup, on_output_lost})`.
4. When `on_setup(true, token)` arrives, it sends non-final
   `{Success, clock_port, audio_port:0, audio_port_tcp}` with the UDP clock port and the
   TCP audio port.
5. On failure it sends a final error: `DeviceInUse`, `DeviceInitFailed`,
   `DeviceOpenFailed` or `UnexpectedError`, mapped from the `RAAT__OUTPUT_PLUGIN_STATUS_*`
   string (`:972-982`).
6. The setup context then stays open. Output messages arrive on it as non-final
   `{OutputMessage, message}` (the signal path, `:664-673`). `on_output_lost` sends final
   `{Lost, reason}`. Teardown or a new setup sends final `Teardown`.

**`stream`** (`:1250-1296`) requires a `current` setup.

1. It sets `buffer_size_frames = buffer_size * sample_rate`.
2. It creates `stream.new(format, 2 * buffer_size_frames)`.
3. If the setup carried `wire_codec`, it creates `codec.new(wire_codec, format)`.
4. It moves to `BUFFERING`, sends non-final `Buffering`, and starts a 500 ms stats timer.
5. This *stream* context then carries non-final updates:
   - `Ready`, once received frames exceed `buffer_size_frames * ready_threshold`
     (`:106-112`);
   - `Playing` and `Stopped`;
   - `Dropout{samples}`, whenever `get_stats().samples_dropped` rises (`:94-104`);
   - and finally `Ended`, from `end_stream`, `teardown`, a new `setup` or shutdown
     (`cleanup_stream`, `:1058-1088`).

   `first_seq` is validated but otherwise unused in this script.

**`start`** (`:1298-1339`):

- If `time` is given, it is an absolute instant in the endpoint's `get_local_time`
  domain.
- Without it, the start time is `get_local_time(token) + min_offset`. The script also
  fetches the output delay here but does not use it.
- It calls `raat.output.start(token, time, stream_sample, stream)`. In the C layer the
  output plays silence until `time`, then plays from `stream_sample` (section 8.4).

**Seek and flush** have no dedicated requests. The primitives the Core can combine are
`stop` + `start(new stream_sample)`, `end_stream` + `stream(new stream_id)`, or a new
`setup` on a format change. Packets carrying an old `stream_id` are dropped on the
endpoint (`:289-298`). Which combination the Core uses needs the playback capture.

### 13.5 Audio transport: TCP, endpoint listens

- **Listener.** The script opens a TCP listener (backlog 10). It binds inside
  `raat.port_range` when that exists, which is not the case on RoonBridge, and otherwise
  on port 0, with `reuseaddr` (`script-4.lua:502-572`). Its port goes to the Core as
  `audio_port_tcp`.
- **Receive buffer.** If the endpoint defines `raat.recv_buffer_size_hint`, the script
  sets that receive buffer on the listener (`:558-567`). RoonBridge does not define it, so
  the field is optional and endpoint-provided.
- **Connections.** The Core connects as a client. A new connection replaces the old one
  and resets the parser (`:363-382`). Data received with no setup or no stream closes the
  connection (`:396-397`).
- **Framing** (`tcp_parse`, `:252-352`): a stream of commands. Each command is one byte,
  then a fixed-size header in big-endian, sometimes followed by a payload:

| cmd | Name | Header | Payload / effect |
|---|---|---|---|
| 0 | DATA | `int32 nsamples`, `int32 nbytes` | `nbytes` of audio for `nsamples` frames, starting at the current `streamsample`. Written with `stream:write_chmap(streamsample, gain, peak, buf, nsamples, chmap)` (or `write` without chmap). Afterwards `streamsample += nsamples`. |
| 1 | CHMAP | `int32 chmap` | Sets the channel map used by subsequent writes. |
| 2 | STREAMID | `int32 stream_id` | DATA for a different `stream_id` than the current `stream` request is ignored. |
| 3 | STREAMSAMPLE | `int64 sample` | Sets the absolute stream position of the next DATA. |
| 4 | NORMALIZATION | `float64 gain`, `float64 peak` | Metadata for subsequent writes. |
| 5 | CODEC_DATA | same header as DATA | Coded bytes, decoded through `codec:decode_to_stream(...)` when the setup had a `wire_codec`. |

An unknown command closes the audio connection (`:271-273`, `:399-401`). There is no
acknowledgement or retransmission on this channel. Flow control is plain TCP
backpressure, and underruns appear only as `Dropout` on the stream context.

### 13.6 PCM payload layout [verified in C]

- `stream:write` rejects data longer than
  `RAAT__stream_format_compute_buffer_size(format, nsamples)`. For PCM that is
  `channels * nsamples * bits_per_sample / 8` (line 23884). For float it is 4 or 8 bytes
  per sample, times channels.
- The drift-correction reader decodes samples as little-endian. 24-bit is 3 packed bytes:
  `b0<<8 | b1<<16 | b2<<24`. 16-bit is `b0<<16 | b1<<24`. 32-bit is a native int.
  (`RAAT__read_stream_with_drift_correction`, around line 19594.)
- So the wire PCM is **interleaved, little-endian, signed, packed `bits_per_sample/8`
  bytes per sample**, at exactly the `setup` format. This is consistent with the C code.
  A playback capture should confirm it.

### 13.7 Clock protocol: UDP, `clock_port`

The script binds one UDP socket (`:505-556`). Its packets (`:114-212`) are:

| Packet | Layout (big-endian) | Meaning |
|---|---|---|
| `RAATCLKQ` | 8-byte ASCII tag + `int32 rid` (12 bytes) | A query for the receiver's clock. |
| `RAATCLKR` | tag + `int32 rid` + `int64 time_ns` + `int64 delay_ns` (28 bytes) | The reply. `time` is `raat.output.get_local_time(token)`. `delay` is `raat.output.get_output_delay(token)`, or 0. |
| `RAATCLKE` | tag + `int32 rid` (12 bytes) | Error reply: no current setup, `IDLE`, or a failing call. |

**The endpoint as responder** (`:115-147`). Any `RAATCLKQ` arriving on the clock port is
answered straight away, as long as a setup exists. From this the Core can measure the
endpoint's clock and output delay. For a single zone that is presumably how the Core paces
to the DAC clock **[inferred]**.

**The endpoint as follower** (`sync`, `:1119-1208`). On a `sync{host, port, new_source}`
request:

1. The script sends one `RAATCLKQ` every 5 ms to `host:port`, for up to 200 ticks.
2. For each reply it computes `rtt = recv - xmit` and
   `offset = (xmit + rtt/2) - remote_time`, all in `get_local_time` units.
3. After 5 good replies it keeps the offset of the reply with the lowest RTT.
4. If that RTT is under 30 ms, it calls
   `raat.output.set_remote_time(token, offset, new_source)`. Otherwise it defers
   `new_source` to the next sync.
5. It answers final `Success`. When the ticks run out, it answers `Timeout`.

In the C layer this feeds the drift correction of section 8.4, which inserts or drops
dithered samples and so is not bit-perfect while it corrects. Whether the Core ever sends
`sync` to a lone zone, and to which master, needs the playback capture.

### 13.8 Volume

`get_controls_state` (`:696-733`) reports `controls.volume` only if
`raat.volume.is_supported`. It has `type`, `min`, `max`, `value`, `mute` and `info`, all
from `raat.volume.state`. `step` is taken from `state.step` when it lies in 0.01..5.0,
and defaults to 1.0 otherwise. `value` is rounded to that step.

`update_volume` (`:928-970`):

- For an `incremental` type, it calls `increment_volume("up"|"down")` and
  `toggle_mute()`.
- Otherwise:
  - `value` becomes `set_volume(round(value, step))`. The value is first floored when
    `is_double_volume_supported` is false.
  - `increment` becomes `set_volume(clamp(value + inc))`.
  - `mute` becomes `set_mute(bool)`.
  - `toggle_mute` becomes `set_mute(not state.mute)`.
- Changes reach the Core through `raat.volume.state_change_handlers`, as non-final
  `Changed` on `subscribe_controls` (`:643-651`).

**For fixed volume, `is_supported=false` is enough.** The script never touches the other
fields in that case.

### 13.9 Transport-ownership bus (skipped when `raat.transport.is_supported=false`)

With a transport plugin present, the script joins UDP multicast **239.255.90.91:9004**,
binds with `reuseaddr` and uses TTL 0. It exchanges JSON `{"command":"query"|"status",
"owner_id"}` to decide which controller owns the device's front panel (`:424-500`).
RoonBridge has no transport plugin, so this never runs there. A native endpoint without
one sees no bus traffic.

### 13.10 Exact API surface the scripts use

Here "returns" means what the script reads back.

- **`raat.log`:** `trace`, `debug`, `warning`, `error` with variadic message arguments
  (`script-3.lua:37,57,64`, `script-4.lua` throughout).
- **`raat.session`:** `send_message(type:int, buffer)` (`script-3.lua:39`),
  `message_handlers` (`table.insert`, `script-3.lua:68`), `shutdown_handlers`
  (`script-4.lua:1406`), and `set_client_type(string)` when present (`script-4.lua:1211`).
- **Plain fields:** `raat.info` and `raat.platform` (put into the `info` reply). Also
  `raat.codecs`, `raat.port_range` (optional `{start_port, end_port}`) and
  `raat.recv_buffer_size_hint` (optional number).
- **`raat.output`:**
  - fields `is_supported`, `info` (JSON string or nil) and `supported_formats` (array of
    `{sample_rate, bits_per_sample, channels, ...}`);
  - flags `is_get_output_delay_supported` and `is_refresh_supported_formats_supported`;
  - `message_handlers`;
  - `setup(format, {on_setup(ok, token|err), on_output_lost(reason_json|nil)})`;
  - `teardown(token)`, `start(token, time, stream_sample, stream)` and `stop(token)`;
  - `get_local_time(token) → int ns` and `get_output_delay(token) → int ns`;
  - `set_remote_time(token, offset_ns, bool)` and `refresh_supported_formats()`.
- **`raat.volume`:**
  - fields `is_supported`, `is_double_volume_supported` and `info`;
  - `state{type,min,max,value,mute,step}`;
  - `state_change_handlers`;
  - `set_volume(n)`, `set_mute(b)`, `increment_volume("up"|"down")` and `toggle_mute()`.
  - Also `raat.volume.type`, which no C build provides, so the check against `"none"` is
    always true (`:699`).
- **`raat.transport`:** `is_supported`, `is_update_status_supported`,
  `is_update_artwork_supported`, `info`, `control_handlers`, `update_status(json)` and
  `update_artwork(mime|nil, blob)`.
- **`raat.source_selection`:** `is_supported`, `is_standby_supported`, `info`,
  `state.status`, `state_change_handlers`, `request_standby(cb)`, `request_source(cb)`
  and `request_source_v2(json, cb)`.
- **`raat.app_channel`:** optional as a whole (`script-4.lua:628`). When present it has
  `is_supported`, `message_handlers` and `send_message(channel, json)`.
- **`buffer` (global):**
  - `new(size|string)`;
  - `length()`;
  - `set_string(off, str[, src_off, len])` and `get_string(off, len)`;
  - `set_uint8` and `get_uint8`;
  - `set_int32_be` and `get_int32_be`;
  - `set_int64_be` and `get_int64_be`;
  - `get_float64_be`.
- **`stream` (global):**
  - `has_write_chmap`;
  - `new(format, capacity)`;
  - `obj:write(sample, gain, peak, buf, n)` and
    `obj:write_chmap(sample, gain, peak, buf, n, chmap)`;
  - `obj:clear()`;
  - `obj:get_stats(tbl)`. It is passed a reusable table and reads `samples_dropped`.
- **`codec` (global):** `new(name, format)` and
  `obj:decode_to_stream(stream, sample, gain, peak, buf, n)`.
- **luv as `uv`:**
  - `new_udp`, `new_tcp` and `new_timer`;
  - `udp_getsockname`, `tcp_getsockname`, `udp_send`, `udp_recv_start`,
    `udp_recv_start_noalloc` (optional) and `udp_recv_stop`;
  - `recv_buffer_size`;
  - handle methods `bind`, `listen`, `accept`, `read_start`, `read_start_noalloc`
    (optional), `close`, `set_membership`, `set_multicast_ttl`, `send`, and on timers
    `start` and `stop`.

  The `*_noalloc` variants and `recv_buffer_size` are Roon additions to luv
  (`native/lua_reg_tables.txt`, for example `read_start_noalloc` at `FUN_002166f0` and
  `udp_recv_start_noalloc` at `FUN_00216850`). They are probed with `if uv.x then`, so
  they are optional.
- **Lua stdlib:** `math`, `string.format`, `table.insert`, `pcall`, `collectgarbage`,
  `os.exit`, `tonumber`, `setmetatable` and `require`.

### 13.11 Hazards for an implementer

- **`force_exit` kills the whole process** through `os.exit(1)`. RoonBridge's supervisor
  restarts RAATServer afterwards. A native endpoint must either run under a supervisor or
  replace `os.exit` in the session VM with "close this session".
- **`request_source` and `request_standby` with source selection unsupported.** The
  script sends `Success` and then falls through to call a nil function
  (`:846-879`). That raises a Lua error, which tears down the whole session (section 10,
  item 7). It is harmless only as long as the Core never sends these requests to such
  devices. Reproduce the behaviour as is; do not "fix" the script.
- **`teardown` never sends a final reply on its own request context** (`:1090-1117`).
  Under section 10, item 1 that leaves a request open on the Core side. This is the
  reference behaviour, so the endpoint's C layer must not add one, because the script
  owns the session layer.
- **`get_local_time` and `get_output_delay` are called from the UDP clock callback**
  on every query (`:115-147`). They must be cheap and thread-safe with respect to the
  audio thread.

## 14. Playback capture (capture3)

**Source.** `capture3/raat.pcap`, 75 s, both directions, TCP and UDP, between the Core
(192.0.2.19) and the R26 (192.0.2.46) running RoonBridge on the mainline kernel,
plus `capture3/hw_params.txt`, the ALSA state during playback. Taken on 2026-11-24.
User actions (KST): 15:20:34 zone selected, 15:20:36 play (resume of a paused queue,
44.1 kHz track), 15:20:52 seek +30 s, 15:21:00 pause, 15:21:06 play, 15:21:14 next
track, 15:21:26 pause. Times below are packet times, written `c3 hh:mm:ss.mmm`.

The session was already set up when the capture started (no `load_script`, `info`
or `set_client_type`), and the manager connection carried only keepalives.

**Capture loss.** The capture tool dropped packets: 97 bytes of the endpoint's session
replies and about 0.25 MB and 0.38 MB of the second and third audio connections are
missing. `tools/ll_decode.py` stops at the first hole; the replay test
(`src/tests/capture.py`) rebuilds streams from all segments, resyncs after holes and
accounts for them. The two reply holes are exactly 64 bytes (`Ready` + `Playing` on
rid 10, c3 15:20:52.62-.72) and 33 bytes (`Playing` on rid 16, c3 15:21:06.66): the
lengths match those frames, and the script must have sent them there.

### 14.1 Requests and replies

| c3 | Core → endpoint | Endpoint → Core |
|---|---|---|
| 15:20:37.050 | `setup` rid 6, `format{sample_type:"pcm", sample_rate:44100, bits_per_sample:16, channels:2, sample_subtype:"none"}` | rid 6 non-final `OutputMessage` (.082), then rid 6 non-final `{Success, clock_port, audio_port:0, audio_port_tcp}` (.112) |
| 15:20:37.123 | `stream` rid 7 `{stream_id, first_seq:-1, nak_port:-1, buffer_size:10, ready_threshold:0.2}` | rid 7 `Buffering` (.125), `Ready` (.173) |
| 15:20:37.174 | `start` rid 8 `{min_offset:69115646, stream_sample:0}` | rid 7 `Playing`, rid 8 final `{Success, time:184759306}` |
| 15:20:52.557 | `end_stream` rid 9 (seek) | rid 7 final `Ended`, rid 9 final `Success` |
| 15:20:52.618 | `stream` rid 10 (`stream_id` + 1), then `start` rid 11 | `Buffering`, [`Ready`, `Playing` lost], rid 11 `Success` |
| 15:21:00.527 | `stop` rid 12 (pause) | rid 10 `Stopped`, rid 12 `Success` |
| 15:21:05.528 | `end_stream` rid 13, `teardown` rid 14 | rid 10 `Ended`, rid 13 `Success`, rid 6 final `Teardown` (.632); nothing on rid 14 |
| 15:21:06.548 | `setup` rid 15 (same format), `stream` rid 16, `start` rid 17 | as for rid 6-8 |
| 15:21:14.555 | `end_stream` rid 18 (next track) | rid 16 `Ended`, rid 18 `Success` |
| 15:21:15.900 | `stream` rid 19, `start` rid 20 (16.164) | `Buffering`, `Ready`, `Playing`, `Success` |
| 15:21:26.582 | `stop` rid 21 (pause); 15:21:31.584 `end_stream` rid 22, `teardown` rid 23 | as for rid 12-14 |

- **No `sync`, no `time` in `start`.** A lone zone is paced by the endpoint's own clock
  (section 14.5). The script computed `time = get_local_time + min_offset` and returned it.
- **Order inside setup.** The signal-path `OutputMessage` reaches the Core *before* the
  setup `Success`: the output plugin posts it while setting up, ahead of `on_setup`.
  Its element is `{type:"output", method:"alsa", quality:"lossless", alsa_device:{name,
  id, longname, components, usbid, driver, mixername}}`, the same card object as in
  `output.info`. There is one element only.
- `teardown` gets no reply on its own rid (section 13.11); the setup context gets
  `Teardown` about 100 ms later.
- The `start` `Success` came 43 ms after `Playing` (c3 15:20:37.179 vs .222). That is
  Nagle against delayed ACK on the endpoint's socket (`TCP_NODELAY` off, section 5.1),
  not processing time **[inferred]**.

### 14.2 Output setup on the device

`hw_params.txt` during playback: `S32_LE`, 2 channels, 44100 Hz, period 882 and buffer
1764 frames (two 20 ms periods, 40 ms), `RW_INTERLEAVED`. The G20's USB interface has
only `S32_LE` altsets (24 and 32 valid bits), so the 16-bit stream was widened into a
32-bit container. The R26 nevertheless offered 16, 24 and 32 bits (section 13.4), so
the endpoint, not the Core, does the widening. Widening is lossless; a bit-perfect
endpoint may do the same.

### 14.3 Audio connection

- **One TCP connection per `stream`.** Each `stream` request is followed about 3 ms
  later by a new connection to the same `audio_port_tcp` (four connections, ports
  34008, 52384, 49990, 41906). The listener port stays the same across setups (39655),
  as does the clock port (54541): the script's sockets live as long as the session.
- **Command order** on every connection: `STREAMID` (= the request's `stream_id`),
  `STREAMSAMPLE 0`, `CHMAP -1`, then `DATA` commands only. No `NORMALIZATION`
  (`tcp_gain` stays 0.0) and no `CODEC_DATA` were sent.
- **Chunks.** Every `DATA` is 15000 frames, 60000 bytes (16-bit stereo, 340 ms at
  44.1 kHz), including the last one before an `end_stream`.
- **Pacing.** An initial burst, then real-time pacing at one chunk per 340 ms. The burst
  was 240000 frames (5.44 s) within 0.1-0.15 s for the first and the next-track stream,
  180000 (4.08 s) after the seek and 135000 (3.06 s) after the resume; the lead over
  real time then stayed at that level (5.4, 4.0, 3.0 and 5.3 s). So the Core keeps at
  most about `0.54 * buffer_size` in flight here **[whether that scales with rate or
  buffer_size is open]**. `Ready` came after the sixth chunk (90000 > 0.2 * 441000
  frames), about 50 ms after the first byte, and the Core sent `start` within 1 ms.
- The Core stops sending at `stop`; the rest of the buffer is dropped by `end_stream`.

### 14.4 Seek, pause, resume, track change

- **Seek** = `end_stream`, then `stream` with `stream_id + 1` on a new audio connection
  from `STREAMSAMPLE 0`, then `start{stream_sample:0}`. No new `setup`.
- **Pause** = `stop`. After 5.0 s of pause the Core sent `end_stream` and `teardown`
  (both pauses: 15:21:00.527 → 05.528 and 15:21:26.582 → 31.584).
- **Resume** after that = a full new `setup` (same format), `stream`, `start`. A resume
  inside the 5 s window, which would `start` again from `STOPPED`, was not captured.
- **Next track** (same format) = `end_stream`, then 1.35 s later `stream` and `start`.
  No new `setup`. A natural track end (gapless) and a format change were not captured.
- Each stream counts its samples from 0; `first_seq` is -1 throughout.

### 14.5 Clock exchange

- The Core queries the endpoint (`RAATCLKQ` from Core port 36916 to the clock port) in
  **bursts of three, 5 ms apart, every 2.0 s** (22 bursts). The first burst follows the
  setup `Success` by 1 ms, and one burst precedes every `stream` request. There are none
  while stopped or between `end_stream` and the next `stream`. RTTs were 0.2-0.7 ms,
  one 1.9 ms.
- **`time`** (the endpoint's `get_local_time`) was 0.0526 s at the first query, 62 ms
  after the `setup` request: the clock starts at 0 with the output. It runs at wall rate (14.048 s of local
  time over 14.048 s of capture time). Across `teardown` and the next `setup` it
  **resumed from where it had stopped**: about 0.95 s is missing from it, close to the
  0.92 s between the `Teardown` and the next `setup` (15:21:05.632 → 06.548). So the clock counts time with an output set up, and
  carries over between setups of the same device.
- **`delay`** was 49092970-49206349 ns, that is 2165-2170 frames at 44.1 kHz, steady
  from the first query after setup on. With a 1764-frame ALSA buffer that is the buffer
  plus about 400 frames (9 ms), presumably USB in flight **[inferred]**.
- **`min_offset` = last delay + 20 ms** exactly, in all four `start`s (69115646 =
  49115646 + 20000000, and likewise). The `start` reply's `time` is then
  `get_local_time + min_offset`: 184759306 for the first, so the clock read 115.6 ms at
  that `start`.

### 14.6 What the endpoint in `src/` does with this

The `TODO(playback capture)` stubs are gone; each place cites this section. The ring is
the full request when it fits a byte budget and never below `0.3 * request`
(`0.6 * buffer_size`, which covers the 5.4 s lead). The ALSA default is a 40 ms buffer in
two periods. 16-bit may go into `S32_LE`. `get_output_delay` is the device queue right
after a write. The clock starts at 0 and carries across setups. The signal path is sent
before `on_setup`, and `sample_subtype` other than `"none"` is refused. `set_remote_time`
still only records its offset (no `sync` for a lone zone), and gain and chmap are still
recorded and not applied. `src/tests/replay.py` replays capture3's requests and audio
against the null output, checks the replies and the clock against it, and checks the
output dump bit for bit (16 → S32_LE) at the frame the start time names.
