import React, { useState } from "react";
import type { DelayRange } from "@/lib/test-run.ts";
import {
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
} from "@/components/ui/input-group.tsx";

type Props = {
  delayRange: DelayRange;
  setDelayRange: (delayRange: DelayRange) => void;
  disabled: boolean;
};

export const DelayRangeInput: React.FC<Props> = ({
  delayRange,
  setDelayRange,
  disabled,
}) => {
  const [from, setFrom] = useState<string>(delayRange.from.toString());
  const [to, setTo] = useState<string>(delayRange.to.toString());
  const [step, setStep] = useState<string>(delayRange.step.toString());

  return (
    <div className="flex gap-x-4 sm:gap-x-8 gap-y-2 items-center flex-wrap">
      <div className="flex gap-2 items-center">
        <span className="text-sm">From</span>
        <InputGroup className="max-w-25">
          <InputGroupInput
            className="text-right"
            disabled={disabled}
            value={from}
            onChange={(e) => {
              const numericValue = Number(e.target.value);
              if (numericValue >= 0) {
                setFrom(e.target.value);
                setDelayRange({ ...delayRange, from: numericValue });
              }
            }}
          />
          <InputGroupAddon align="inline-end" className="pb-1">
            ms
          </InputGroupAddon>
        </InputGroup>
      </div>

      <div className="flex gap-2 items-center">
        <span className="text-sm">To</span>
        <InputGroup className="max-w-25">
          <InputGroupInput
            className="text-right"
            disabled={disabled}
            value={to}
            onChange={(e) => {
              const numericValue = Number(e.target.value);
              if (numericValue >= 0) {
                setTo(e.target.value);
                setDelayRange({ ...delayRange, to: numericValue });
              }
            }}
          />
          <InputGroupAddon align="inline-end" className="pb-1">
            ms
          </InputGroupAddon>
        </InputGroup>
      </div>

      <div className="flex gap-2 items-center">
        <span className="text-sm">Step</span>
        <InputGroup className="max-w-25">
          <InputGroupInput
            className="text-right"
            disabled={disabled}
            value={step}
            onChange={(e) => {
              const numericValue = Number(e.target.value);
              if (numericValue >= 0) {
                setStep(e.target.value);
                setDelayRange({ ...delayRange, step: numericValue });
              }
            }}
          />
          <InputGroupAddon align="inline-end" className="pb-1">
            ms
          </InputGroupAddon>
        </InputGroup>
      </div>
    </div>
  );
};
