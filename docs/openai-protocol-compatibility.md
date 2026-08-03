# OpenAI/Codex protocol compatibility

This matrix covers wire compatibility only. Payment, account management, quota,
and Relay/Provider scheduling are outside its scope. Sub2API was used as a
behavioral checklist; the implementation is based on MycoMesh code and the
OpenAI Responses wire schema.

| Area | MycoMesh V7 status | Notes |
| --- | --- | --- |
| Responses HTTP aliases | Supported | `/responses`, `/v1/responses`, and `/v1/v1/responses`. |
| Responses SSE lifecycle | Supported, buffered | Includes `sequence_number`, zero indices, required empty arrays/strings, item/part/text/reasoning/tool events, and terminal status events. |
| Chat Completions SSE | Supported, buffered | Emits `chat.completion.chunk`, tool-call deltas, optional usage chunk, and `[DONE]`. |
| Function/custom tool calls | Supported | Required `call_id`, `name`, `arguments`/`input`, namespace/caller preservation, and continuation events. |
| Tool output continuation | Supported | Recognizes `function_call_output`, `tool_search_output`, `custom_tool_call_output`, and `mcp_tool_call_output`. |
| Provider failover during a tool turn | Supported when context is complete | A new Provider can rebuild a continuation when matching call and output items are present. A bare `item_reference` is not treated as reconstructable. |
| Responses WebSocket client transport | Supported, sequential bridge | V7 Consumer accepts `response.create` and returns Responses events as WebSocket JSON frames. It keeps no Consumer session and bridges each request through Relay HTTP. |
| OpenAI error envelope | Supported | HTTP errors use `error.message/type/param/code`; WebSocket errors use the Responses `error` event shape. |
| Current Responses request fields | Transport supported | Fields are included in the signed request hash and carried across Consumer, Relay, and Provider. Backend-specific execution limits still apply. |
| Unknown output item types | Preserved | They still receive output-item added/done events rather than being silently discarded. |
| `/responses/compact` and remote compaction v2 | Supported | Explicit compact requests and `compaction_trigger` are sent through the Provider's native Codex OAuth Responses channel. Unary results are encoded as the minimal compact SSE lifecycle when the client requested a stream. |
| Compacted-context continuation | Supported | Requests carrying `compaction`, encrypted reasoning, or `item_reference` input stay on the native Responses channel, so the Consumer does not retain response/session state. |
| Native token-latency streaming | Not available on V7 app-server Provider | Responses are buffered at the Provider and encoded into a valid stream at the Consumer. The response header reports `x-mycomesh-streaming-mode: buffered`. |
| Native upstream WebSocket pooling/multiplexing | Not implemented | The Consumer bridge supports one in-flight request at a time per connection, matching the sequential client contract. |

Normal inference remains on Codex app-server. Protocol operations that require
opaque native state use the official Codex login only on the Provider and never
move OAuth credentials, response state, or sessions into the Consumer.
