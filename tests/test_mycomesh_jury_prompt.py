"""A juror reads a case as a transcript: the tools offered, the conversation with its tool calls and results,
the Provider's answer, and the images the conversation carried."""
from __future__ import annotations

import unittest

from mycomesh.jury import DEFAULT_POLICY, juror_prompt


class JurorPromptTest(unittest.TestCase):
    def test_tool_calls_results_and_images_are_laid_out(self) -> None:
        image = "data:image/png;base64,iVBORw0KGgo="
        request = {"endpoint": "chat", "model": "gpt-5.5", "options": {"tools": [
            {"type": "function", "function": {"name": "Bash", "description": "run a shell command",
                                              "parameters": {"type": "object", "properties": {"command": {"type": "string"}}}}}]},
                   "messages": [{"role": "system", "content": "You are an agent."},
                                {"role": "user", "content": [{"type": "text", "text": "what is in the screenshot? then list files"},
                                                             {"type": "image_url", "image_url": {"url": image}}]},
                                {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "Bash", "arguments": '{"command":"ls"}'}}]},
                                {"role": "tool", "tool_call_id": "c1", "content": "a.txt\n" + "x" * 5000}]}
        response = {"output": {"choices": [{"message": {"role": "assistant", "content": "A login page.", "tool_calls": [
            {"id": "c2", "type": "function", "function": {"name": "Bash", "arguments": '{"command":"cat a.txt"}'}}]}}]}}
        evidence = {"allegation": {"reason_code": "unrelated_response", "statement": "it ran the wrong command"},
                    "signed_receipt": {"receipt": {"input_tokens": 900, "output_tokens": 40, "actual_fee": 314}}}
        system, user = juror_prompt(evidence, request, response)
        self.assertEqual(system["content"], DEFAULT_POLICY["system_prompt"])
        self.assertIn("tool calls", DEFAULT_POLICY["system_prompt"])
        text = user["content"][0]["text"]
        for expected in ("Allegation: unrelated_response: it ran the wrong command", "- Bash: run a shell command parameters=",
                         "[system] You are an agent.", "[user] what is in the screenshot? then list files[image 1 attached below]",
                         '[assistant calls tool] Bash({"command":"ls"}) id=c1', "[tool result for c1] a.txt", "truncated",
                         "[assistant] A login page.", '[assistant calls tool] Bash({"command":"cat a.txt"}) id=c2'):
            self.assertIn(expected, text)
        self.assertEqual(user["content"][-1], {"type": "image_url", "image_url": {"url": image}})


if __name__ == "__main__":
    unittest.main()
