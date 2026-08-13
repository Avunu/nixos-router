import { useRef, useState } from "react";
import { errMsg } from "./nix";
import {
  Form,
  FormGroup,
  TextInput,
  FormSelect,
  FormSelectOption,
  Button,
  CodeBlock,
  CodeBlockCode,
  Flex,
  FlexItem,
} from "@patternfly/react-core";

const _ = cockpit.gettext;

const TOOLS: Record<string, string[]> = {
  ping: ["ping", "-c", "5"],
  traceroute: ["traceroute"],
  dig: ["dig", "+noall", "+answer", "+stats"],
  mtr: ["mtr", "--report", "--report-cycles", "5"],
};

export const Diagnostics = () => {
  const [tool, setTool] = useState("ping");
  const [target, setTarget] = useState("1.1.1.1");
  const [out, setOut] = useState("");
  const [running, setRunning] = useState(false);
  const procRef = useRef<CockpitProcess | null>(null);

  const run = () => {
    if (!target.trim()) {
      return;
    }
    setOut("");
    setRunning(true);
    const argv = [...(TOOLS[tool] ?? []), target.trim()];
    const proc = cockpit.spawn(argv, { err: "out", pty: false });
    procRef.current = proc;
    void proc.stream((data: string) => setOut((o) => o + data));
    proc
      .then(() => setRunning(false))
      .catch((e: unknown) => {
        setOut((o) => `${o}\n${errMsg(e)}`);
        setRunning(false);
      });
  };

  const cancel = () => {
    if (procRef.current) {
      procRef.current.close("cancelled");
    }
    setRunning(false);
  };

  return (
    <>
      <Form
        isHorizontal
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <FormGroup label={_("Tool")} fieldId="tool">
          <FormSelect
            id="tool"
            value={tool}
            onChange={(_e, v) => setTool(v)}
            aria-label={_("Tool")}
          >
            {Object.keys(TOOLS).map((t) => (
              <FormSelectOption key={t} value={t} label={t} />
            ))}
          </FormSelect>
        </FormGroup>
        <FormGroup label={_("Target")} fieldId="target">
          <Flex>
            <FlexItem grow={{ default: "grow" }}>
              <TextInput
                id="target"
                value={target}
                onChange={(_e, v) => setTarget(v)}
                placeholder={_("host or IP address")}
              />
            </FlexItem>
            <FlexItem>
              {running ? (
                <Button variant="danger" onClick={cancel}>
                  {_("Cancel")}
                </Button>
              ) : (
                <Button variant="primary" onClick={run}>
                  {_("Run")}
                </Button>
              )}
            </FlexItem>
          </Flex>
        </FormGroup>
      </Form>
      {out && (
        <CodeBlock>
          <CodeBlockCode>{out}</CodeBlockCode>
        </CodeBlock>
      )}
    </>
  );
};
