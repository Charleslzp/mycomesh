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
| `/responses/compact` wire encoding | Implemented | The shared encoder can emit compact output-item/done plus terminal events. |
| Actual remote compaction on Codex app-server | Not available | HTTP and WebSocket return explicit `unsupported_endpoint` before charging. No fake encrypted compaction item is produced. |
| Native token-latency streaming | Not available on V7 app-server Provider | Responses are buffered at the Provider and encoded into a valid stream at the Consumer. The response header reports `x-mycomesh-streaming-mode: buffered`. |
| Native upstream WebSocket pooling/multiplexing | Not implemented | The Consumer bridge supports one in-flight request at a time per connection, matching the sequential client contract. |

True remote compaction and native token streaming require a Provider backend
that exposes the upstream Responses protocol directly. They cannot be derived
faithfully from a completed Codex app-server turn.
