"""A MycoMesh Provider backend plugin: copy into ~/.mycomesh/provider/plugins/ and start with

    mycomesh-provider start --backend my-model --backend-option api_key=env:MY_MODEL_KEY --model my-model-v1

Replace the body of ``backend`` with a call to your model. Streaming is optional.
"""
import json
import urllib.request

from mycomesh.provider.plugins import BackendError, register, shape_output


@register("my-model", description="template: POST the prompt to an HTTP endpoint (options: url, api_key)")
def make_backend(options, context):
    url = options.get("url", "http://127.0.0.1:9000/generate")
    api_key = options.get("api_key", "")

    def backend(request, on_delta=None):
        # The request is OpenAI-shaped: chat has "messages", responses has "input".
        prompt = request["input"] if request["endpoint"] == "responses" else request["messages"]
        body = json.dumps({"model": request["model"], "prompt": prompt, "max_tokens": request["max_output_tokens"]}).encode()
        headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {api_key}"} if api_key else {})}
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers), timeout=context.timeout) as reply:
                result = json.loads(reply.read())
        except OSError as exc:
            raise BackendError(f"my-model unreachable: {exc}") from exc
        text = result["text"]
        input_tokens, output_tokens = int(result.get("input_tokens", 0)), int(result.get("output_tokens", 0))
        # Token counts set the fee at the network price: report what the model really used.
        return shape_output(request, text, input_tokens, output_tokens), input_tokens, output_tokens

    return backend
