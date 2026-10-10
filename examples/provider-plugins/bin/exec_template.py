#!/usr/bin/env python3
"""A MycoMesh ``exec`` backend in any language (this one is Python). Start with

    mycomesh-provider start --backend exec --backend-option "command=python3 /plugins/bin/exec_template.py" --model my-model

Keep exec programs in plugins/bin/: every *.py directly in plugins/ is imported as a Python plugin.

Protocol: one JSON request on stdin; JSON lines on stdout: optional {"delta": "..."} while streaming,
then {"output_text": "...", "input_tokens": N, "output_tokens": M}; or {"error": "..."}.
"""
import json
import sys


def main() -> None:
    request = json.loads(sys.stdin.readline())
    prompt = request["input"] if request["endpoint"] == "responses" else request["messages"][-1]["content"]
    answer = f"You asked: {prompt}"            # call your model here
    for word in answer.split(" "):              # stream as it is generated (optional)
        print(json.dumps({"delta": word + " "}), flush=True)
    print(json.dumps({"output_text": answer, "input_tokens": len(str(prompt)) // 4, "output_tokens": len(answer) // 4}))


if __name__ == "__main__":
    main()
